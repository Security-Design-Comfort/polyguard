//! Stage 5: Content Disarm & Reconstruction (CDR) for JPEG, PNG, ZIP, and PDF,
//! plus subprocess worker isolation with wall-clock timeouts, Unix `setrlimit`
//! (`RLIMIT_AS` + `RLIMIT_DATA` fallback + `RLIMIT_CPU` + `RLIMIT_CORE`), Windows
//! Job Object memory caps, and optional isolated external PDF rebuilder fallback.

use crate::ingest::{validate_image_dimensions, validate_zip_budget, validate_zip_entry_path};
use crate::types::{FileFormat, PolicyConfig, PolyguardError, Result, SanitizationSummary};
use image::codecs::jpeg::{JpegDecoder, JpegEncoder};
use image::codecs::png::{CompressionType, FilterType, PngDecoder, PngEncoder};
use image::{DynamicImage, ExtendedColorType, ImageDecoder, ImageEncoder, Limits};
use lopdf::{Dictionary, Document, Object};
use memchr::memmem;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Execution strategy for Stage 5 CDR reconstruction.
#[derive(Debug, Clone)]
pub enum IsolationContext {
    Subprocess { worker_bin: PathBuf },
    InProcess,
}

impl IsolationContext {
    pub fn from_current_exe(config: &PolicyConfig) -> Self {
        if config.enable_process_isolation {
            if let Ok(exe) = std::env::current_exe() {
                return Self::Subprocess { worker_bin: exe };
            }
        }
        Self::InProcess
    }
}

/// Apply Unix `RLIMIT_AS` (falling back to `RLIMIT_DATA` on restricted kernels/macOS),
/// `RLIMIT_CPU`, and `RLIMIT_CORE = 0` inside the isolated worker subprocess.
#[cfg(unix)]
pub fn apply_worker_resource_limits(config: &PolicyConfig) -> Result<()> {
    let mem = config.worker_memory_limit_bytes as libc::rlim_t;
    let mem_rlim = libc::rlimit {
        rlim_cur: mem,
        rlim_max: mem,
    };
    // SAFETY: valid pointer to an initialized `libc::rlimit`.
    let rc_as = unsafe { libc::setrlimit(libc::RLIMIT_AS, &mem_rlim) };
    if rc_as != 0 {
        let _ = unsafe { libc::setrlimit(libc::RLIMIT_DATA, &mem_rlim) };
    }

    let cpu_secs = (config.worker_timeout_ms / 1000).max(1) as libc::rlim_t;
    let cpu_rlim = libc::rlimit {
        rlim_cur: cpu_secs,
        rlim_max: cpu_secs.saturating_add(1),
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu_rlim) };

    // Disable core dumps for untrusted payloads.
    let core_zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_zero) };
    Ok(())
}

#[cfg(not(unix))]
pub fn apply_worker_resource_limits(_config: &PolicyConfig) -> Result<()> {
    Ok(())
}

/// RAII wrapper keeping a Windows Job Object alive for the lifetime of an isolated child
/// process, enforcing `JOB_OBJECT_LIMIT_PROCESS_MEMORY` and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
#[cfg(windows)]
struct WindowsJobGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl WindowsJobGuard {
    fn attach(child: &Child, memory_limit_bytes: u64) -> Option<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        };

        // SAFETY: Standard Win32 Job Object creation and configuration with zeroed struct.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.ProcessMemoryLimit = usize::try_from(memory_limit_bytes).unwrap_or(usize::MAX);

            let ok_set = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok_set == 0 {
                CloseHandle(job);
                return None;
            }

            let proc_handle = child.as_raw_handle() as HANDLE;
            if AssignProcessToJobObject(job, proc_handle) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self(job))
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJobGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid Job Object handle owned by this guard.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(not(windows))]
struct WindowsJobGuard;

#[cfg(not(windows))]
impl WindowsJobGuard {
    fn attach(_child: &Child, _memory_limit_bytes: u64) -> Option<Self> {
        None
    }
}

/// Execute Pure Rust CDR directly in-process (also called by `__cdr-worker`).
pub fn sanitize_in_process(
    data: &[u8],
    format: FileFormat,
    config: &PolicyConfig,
) -> Result<(Vec<u8>, Vec<String>)> {
    match format {
        FileFormat::Jpeg => sanitize_jpeg(data, config),
        FileFormat::Png => sanitize_png(data, config),
        FileFormat::Zip => sanitize_zip(data, config),
        FileFormat::Pdf => sanitize_pdf(data, config),
        _ => Err(PolyguardError::UnsupportedFormat(format.to_string())),
    }
}

/// Dispatch CDR using subprocess isolation or in-process execution.
pub fn sanitize_bytes(
    data: &[u8],
    format: FileFormat,
    config: &PolicyConfig,
    isolation: &IsolationContext,
    dry_run: bool,
) -> Result<(Option<Vec<u8>>, SanitizationSummary)> {
    if dry_run {
        return Ok((
            None,
            SanitizationSummary {
                performed: false,
                dry_run: true,
                isolated: matches!(isolation, IsolationContext::Subprocess { .. }),
                original_size: data.len(),
                sanitized_size: data.len(),
                removed_bytes: 0,
                notes: vec![format!(
                    "Dry-run: would reconstruct {} file cleanly and strip all polyglot/metadata regions",
                    format
                )],
            },
        ));
    }

    let (clean_bytes, notes, isolated) = match isolation {
        IsolationContext::Subprocess { worker_bin } if config.enable_process_isolation => {
            let (b, n) = run_isolated_cdr(worker_bin, format, data, config)?;
            (b, n, true)
        }
        _ => {
            let (b, n) = sanitize_in_process(data, format, config)?;
            (b, n, false)
        }
    };

    let sanitized_size = clean_bytes.len();
    Ok((
        Some(clean_bytes),
        SanitizationSummary {
            performed: true,
            dry_run: false,
            isolated,
            original_size: data.len(),
            sanitized_size,
            removed_bytes: data.len().saturating_sub(sanitized_size),
            notes,
        },
    ))
}

fn run_isolated_cdr(
    worker_bin: &PathBuf,
    format: FileFormat,
    data: &[u8],
    config: &PolicyConfig,
) -> Result<(Vec<u8>, Vec<String>)> {
    let format_arg = match format {
        FileFormat::Jpeg => "jpeg",
        FileFormat::Png => "png",
        FileFormat::Zip => "zip",
        FileFormat::Pdf => "pdf",
        _ => return Err(PolyguardError::UnsupportedFormat(format.to_string())),
    };
    let policy_json = serde_json::to_string(config)
        .map_err(|e| PolyguardError::IsolationFailed(format!("serialize policy: {}", e)))?;

    let mut child = Command::new(worker_bin)
        .args(["__cdr-worker", "--format", format_arg, "--policy-json", &policy_json])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PolyguardError::IsolationFailed(format!("spawn worker failed: {}", e)))?;

    // Attach Windows Job Object memory cap (no-op on Unix, which uses `setrlimit`).
    let _job_guard = WindowsJobGuard::attach(&child, config.worker_memory_limit_bytes);

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| PolyguardError::IsolationFailed("missing stdin".into()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| PolyguardError::IsolationFailed("missing stdout".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| PolyguardError::IsolationFailed("missing stderr".into()))?;

    let max_out = config.max_file_size_bytes.saturating_mul(2);
    let timeout = Duration::from_millis(config.worker_timeout_ms);
    let started = Instant::now();

    let (out_bytes, err_text) = std::thread::scope(|s| -> Result<(Vec<u8>, String)> {
        let w = s.spawn(move || {
            let _ = stdin.write_all(data);
            drop(stdin);
        });
        let o = s.spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.by_ref().take(max_out).read_to_end(&mut buf);
            buf
        });
        let e = s.spawn(move || {
            let mut buf = String::new();
            let _ = stderr.by_ref().take(64 * 1024).read_to_string(&mut buf);
            buf
        });

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let _ = w.join();
                    let out = o.join().unwrap_or_default();
                    let err = e.join().unwrap_or_default();
                    if !status.success() {
                        return Err(PolyguardError::IsolationFailed(format!(
                            "worker exited with {}: {}",
                            status,
                            err.trim()
                        )));
                    }
                    return Ok((out, err));
                }
                Ok(None) if started.elapsed() >= timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = w.join();
                    let _ = o.join();
                    let _ = e.join();
                    return Err(PolyguardError::IsolationTimeout {
                        timeout_ms: config.worker_timeout_ms,
                    });
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(err) => {
                    let _ = child.kill();
                    return Err(PolyguardError::IsolationFailed(format!("try_wait error: {}", err)));
                }
            }
        }
    })?;

    let mut notes: Vec<String> = err_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    notes.push("Executed inside isolated worker subprocess with OS resource limits".into());
    Ok((out_bytes, notes))
}

// ============================================================================
// Image CDR (JPEG & PNG Destructive Re-encoding + LSB Normalization)
// ============================================================================

fn image_limits(config: &PolicyConfig) -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(config.max_image_width);
    limits.max_image_height = Some(config.max_image_height);
    limits.max_alloc = Some(config.max_decode_memory_bytes);
    limits
}

/// Clears the least significant bit (bit 0) of RGB color channels in an interleaved
/// RGB8 (`stride = 3`) or RGBA8 (`stride = 4`) pixel buffer to destroy hidden LSB payloads
/// while preserving alpha opacity on RGBA images.
#[inline]
pub fn strip_rgb_lsb(pixels: &mut [u8], stride: usize) {
    debug_assert!(stride == 3 || stride == 4);
    for px in pixels.chunks_exact_mut(stride) {
        px[0] &= 0xFE;
        px[1] &= 0xFE;
        px[2] &= 0xFE;
    }
}

fn sanitize_jpeg(data: &[u8], config: &PolicyConfig) -> Result<(Vec<u8>, Vec<String>)> {
    let soi = memmem::find(data, b"\xFF\xD8")
        .ok_or_else(|| PolyguardError::SanitizationFailed("JPEG SOI marker not found".into()))?;
    let slice = &data[soi..];

    let mut dec = JpegDecoder::new(Cursor::new(slice))
        .map_err(|e| PolyguardError::SanitizationFailed(format!("JPEG decode init: {}", e)))?;
    let (w, h) = dec.dimensions();
    validate_image_dimensions(w, h, config)?;
    dec.set_limits(image_limits(config))
        .map_err(|e| PolyguardError::SanitizationFailed(format!("JPEG limits: {}", e)))?;

    let mut rgb = DynamicImage::from_decoder(dec)
        .map_err(|e| PolyguardError::SanitizationFailed(format!("JPEG decode: {}", e)))?
        .to_rgb8();

    if config.strip_lsb_on_sanitize {
        strip_rgb_lsb(rgb.as_mut(), 3);
    }

    let mut clean = Vec::with_capacity(slice.len().min(4 * 1024 * 1024));
    JpegEncoder::new_with_quality(&mut clean, config.jpeg_reencode_quality)
        .encode(rgb.as_raw(), rgb.width(), rgb.height(), ExtendedColorType::Rgb8)
        .map_err(|e| PolyguardError::SanitizationFailed(format!("JPEG re-encode: {}", e)))?;

    let mut notes = vec![
        format!(
            "Destructively re-encoded {}x{} RGB8 JPEG (q={})",
            rgb.width(),
            rgb.height(),
            config.jpeg_reencode_quality
        ),
        "Stripped all APPn/EXIF/XMP/COM metadata, pre-SOI bytes, and post-EOI payloads".into(),
    ];
    if config.strip_lsb_on_sanitize {
        notes.push("Normalized RGB least significant bit plane prior to re-encoding".into());
    }

    Ok((clean, notes))
}

fn sanitize_png(data: &[u8], config: &PolicyConfig) -> Result<(Vec<u8>, Vec<String>)> {
    let sig = memmem::find(data, b"\x89PNG\r\n\x1a\n")
        .ok_or_else(|| PolyguardError::SanitizationFailed("PNG signature not found".into()))?;
    let slice = &data[sig..];

    let mut dec = PngDecoder::new(Cursor::new(slice))
        .map_err(|e| PolyguardError::SanitizationFailed(format!("PNG decode init: {}", e)))?;
    let (w, h) = dec.dimensions();
    validate_image_dimensions(w, h, config)?;
    dec.set_limits(image_limits(config))
        .map_err(|e| PolyguardError::SanitizationFailed(format!("PNG limits: {}", e)))?;

    let mut rgba = DynamicImage::from_decoder(dec)
        .map_err(|e| PolyguardError::SanitizationFailed(format!("PNG decode: {}", e)))?
        .to_rgba8();

    if config.strip_lsb_on_sanitize {
        strip_rgb_lsb(rgba.as_mut(), 4);
    }

    let mut clean = Vec::with_capacity(slice.len().min(4 * 1024 * 1024));
    PngEncoder::new_with_quality(&mut clean, CompressionType::Default, FilterType::Adaptive)
        .write_image(rgba.as_raw(), rgba.width(), rgba.height(), ExtendedColorType::Rgba8)
        .map_err(|e| PolyguardError::SanitizationFailed(format!("PNG re-encode: {}", e)))?;

    let mut notes = vec![
        format!(
            "Destructively re-encoded {}x{} RGBA8 PNG (IHDR/IDAT/IEND)",
            rgba.width(),
            rgba.height()
        ),
        "Stripped all ancillary chunks, pre-header bytes, and post-IEND payloads".into(),
    ];
    if config.strip_lsb_on_sanitize {
        notes.push("Cleared RGB least significant bit plane to neutralize LSB steganography".into());
    }

    Ok((clean, notes))
}

// ============================================================================
// ZIP Archive CDR (Safe Unpack & Canonical Offset-0x00 Repack)
// ============================================================================

fn sanitize_zip(data: &[u8], config: &PolicyConfig) -> Result<(Vec<u8>, Vec<String>)> {
    let mut archive = ZipArchive::new(Cursor::new(data))
        .map_err(|e| PolyguardError::SanitizationFailed(format!("ZIP open failed: {}", e)))?;
    let entry_count = archive.len();
    if entry_count > config.max_zip_entries {
        return Err(PolyguardError::ZipBomb {
            uncompressed: 0,
            compressed: data.len() as u64,
            ratio: f64::INFINITY,
        });
    }

    let mut out_cursor = Cursor::new(Vec::with_capacity(data.len().min(8 * 1024 * 1024)));
    let mut writer = ZipWriter::new(&mut out_cursor);
    let (mut total_uncomp, mut total_comp, mut repacked) = (0u64, 0u64, 0usize);

    for idx in 0..entry_count {
        let mut entry = archive.by_index(idx).map_err(|e| {
            PolyguardError::SanitizationFailed(format!("ZIP entry {} read: {}", idx, e))
        })?;
        let raw_name = entry.name().to_string();
        validate_zip_entry_path(&raw_name)?;
        let safe_path = entry
            .enclosed_name()
            .ok_or_else(|| PolyguardError::ZipSlip { path: raw_name.clone() })?;
        let canonical = safe_path.to_string_lossy().replace('\\', "/");

        if entry.is_dir() {
            let dir_name = if canonical.ends_with('/') {
                canonical
            } else {
                format!("{}/", canonical)
            };
            writer
                .add_directory(
                    dir_name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .map_err(|e| PolyguardError::SanitizationFailed(format!("ZIP dir write: {}", e)))?;
            continue;
        }

        let remaining = config.max_zip_uncompressed_bytes.saturating_sub(total_uncomp);
        let mut content = Vec::new();
        entry.by_ref().take(remaining.saturating_add(1)).read_to_end(&mut content)?;
        if content.len() as u64 > remaining {
            return Err(PolyguardError::ZipBomb {
                uncompressed: total_uncomp.saturating_add(content.len() as u64),
                compressed: total_comp.saturating_add(entry.compressed_size()),
                ratio: f64::INFINITY,
            });
        }

        total_uncomp = total_uncomp.saturating_add(content.len() as u64);
        total_comp = total_comp.saturating_add(entry.compressed_size());
        validate_zip_budget(total_uncomp, total_comp, entry_count, config)?;

        writer
            .start_file(
                &canonical,
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .map_err(|e| PolyguardError::SanitizationFailed(format!("ZIP start_file: {}", e)))?;
        writer
            .write_all(&content)
            .map_err(|e| PolyguardError::SanitizationFailed(format!("ZIP write_all: {}", e)))?;
        repacked += 1;
    }

    writer
        .finish()
        .map_err(|e| PolyguardError::SanitizationFailed(format!("ZIP finish: {}", e)))?;

    Ok((
        out_cursor.into_inner(),
        vec![
            format!("Repacked {} files into canonical ZIP starting at offset 0x00", repacked),
            "Removed pre-header prependers, inter-entry gaps, comments, and trailing bytes".into(),
        ],
    ))
}

// ============================================================================
// Pure Rust PDF CDR + Optional Isolated External Subprocess Fallback
// ============================================================================

const PDF_STRIPPED_KEYS: &[&[u8]] = &[
    b"JS", b"JavaScript", b"OpenAction", b"AA", b"Launch",
    b"RichMedia", b"XFA", b"SubmitForm", b"ImportData", b"GoToR", b"GoToE",
];

fn sanitize_pdf_dict(dict: &mut Dictionary, strip_embedded: bool, count: &mut usize) {
    for &key in PDF_STRIPPED_KEYS {
        if dict.remove(key).is_some() {
            *count += 1;
        }
    }
    if strip_embedded {
        for key in [b"EmbeddedFiles".as_slice(), b"EmbeddedFile".as_slice(), b"EF".as_slice()] {
            if dict.remove(key).is_some() {
                *count += 1;
            }
        }
    }
    let dangerous_action = dict
        .get(b"S")
        .ok()
        .and_then(|o| match o {
            Object::Name(n) => Some(n.as_slice()),
            _ => None,
        })
        .is_some_and(|n| {
            matches!(
                n,
                b"JavaScript" | b"Launch" | b"SubmitForm" | b"ImportData" | b"GoToR" | b"GoToE"
            )
        });
    if dangerous_action {
        dict.remove(b"S");
        dict.remove(b"F");
        dict.remove(b"URI");
        *count += 1;
    }
    for (_, val) in dict.iter_mut() {
        sanitize_pdf_obj(val, strip_embedded, count);
    }
}

fn sanitize_pdf_obj(obj: &mut Object, strip_embedded: bool, count: &mut usize) {
    match obj {
        Object::Dictionary(d) => sanitize_pdf_dict(d, strip_embedded, count),
        Object::Stream(s) => sanitize_pdf_dict(&mut s.dict, strip_embedded, count),
        Object::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_pdf_obj(item, strip_embedded, count);
            }
        }
        _ => {}
    }
}

/// Invoke an external PDF normalizer (`qpdf`, `mutool`, or custom tool) strictly as an
/// isolated child subprocess with wall-clock timeout and bounded output size.
fn run_pdf_external_fallback(
    tool: &str,
    trimmed_pdf: &[u8],
    config: &PolicyConfig,
) -> Result<Vec<u8>> {
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let in_path = std::env::temp_dir().join(format!("polyguard_pdf_in_{pid}_{seq}.pdf"));
    let out_path = std::env::temp_dir().join(format!("polyguard_pdf_out_{pid}_{seq}.pdf"));

    std::fs::write(&in_path, trimmed_pdf)?;

    let tool_name = Path::new(tool)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(tool)
        .to_ascii_lowercase();

    let mut cmd = Command::new(tool);
    if tool_name.contains("qpdf") {
        cmd.arg("--decrypt")
            .arg("--stream-data=uncompress")
            .arg(&in_path)
            .arg(&out_path);
    } else if tool_name.contains("mutool") {
        cmd.arg("clean").arg("-d").arg(&in_path).arg(&out_path);
    } else {
        cmd.arg(&in_path).arg(&out_path);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let result = (|| -> Result<Vec<u8>> {
        let mut child = cmd.spawn().map_err(|e| {
            PolyguardError::SanitizationFailed(format!(
                "failed to spawn pdf_fallback_tool '{}': {}",
                tool, e
            ))
        })?;
        let _job_guard = WindowsJobGuard::attach(&child, config.worker_memory_limit_bytes);

        let timeout = Duration::from_millis(config.worker_timeout_ms);
        let started = Instant::now();
        let status = loop {
            match child.try_wait()? {
                Some(st) => break st,
                None if started.elapsed() >= timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(PolyguardError::IsolationTimeout {
                        timeout_ms: config.worker_timeout_ms,
                    });
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };

        // `qpdf` returns exit code 3 when rebuilding succeeds with non-fatal warnings.
        let ok_exit = status.success() || (tool_name.contains("qpdf") && status.code() == Some(3));
        if !ok_exit {
            let mut err_buf = String::new();
            if let Some(se) = child.stderr.take() {
                let _ = se.take(16 * 1024).read_to_string(&mut err_buf);
            }
            return Err(PolyguardError::SanitizationFailed(format!(
                "pdf_fallback_tool '{}' exited with {}: {}",
                tool,
                status,
                err_buf.trim()
            )));
        }

        let mut rebuilt = Vec::new();
        let file = std::fs::File::open(&out_path)?;
        file.take(config.max_file_size_bytes.saturating_add(1))
            .read_to_end(&mut rebuilt)?;
        if rebuilt.len() as u64 > config.max_file_size_bytes {
            return Err(PolyguardError::FileTooLarge {
                size: rebuilt.len() as u64,
                max: config.max_file_size_bytes,
            });
        }
        Ok(rebuilt)
    })();

    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&out_path);
    result
}

fn sanitize_pdf(data: &[u8], config: &PolicyConfig) -> Result<(Vec<u8>, Vec<String>)> {
    let pdf_start = memmem::find(&data[..data.len().min(1024)], b"%PDF-").ok_or_else(|| {
        PolyguardError::SanitizationFailed("missing %PDF- header within first 1024 bytes".into())
    })?;
    let eof_end = memmem::rfind(&data[pdf_start..], b"%%EOF")
        .map(|rel| {
            let mut end = pdf_start + rel + 5;
            while end < data.len() && (data[end] == b'\r' || data[end] == b'\n') {
                end += 1;
            }
            end
        })
        .unwrap_or(data.len());

    let trimmed = &data[pdf_start..eof_end];
    let mut notes = Vec::new();

    let mut doc = match Document::load_mem(trimmed) {
        Ok(d) => d,
        Err(primary_err) => {
            if let Some(tool) = config.pdf_fallback_tool.as_deref() {
                let rebuilt = run_pdf_external_fallback(tool, trimmed, config)?;
                notes.push(format!(
                    "Normalized complex PDF via isolated external subprocess '{}'",
                    tool
                ));
                Document::load_mem(&rebuilt).map_err(|e| {
                    PolyguardError::SanitizationFailed(format!(
                        "PDF remained unloadable after '{}' fallback: {}",
                        tool, e
                    ))
                })?
            } else {
                return Err(PolyguardError::SanitizationFailed(format!(
                    "Pure Rust lopdf load failed (configure `pdf_fallback_tool` e.g. \"qpdf\" for complex/encrypted PDFs): {}",
                    primary_err
                )));
            }
        }
    };

    let strip_embedded = !config.whitelist.allow_pdf_embedded_files;
    let mut stripped = 0usize;
    for obj in doc.objects.values_mut() {
        sanitize_pdf_obj(obj, strip_embedded, &mut stripped);
    }
    sanitize_pdf_dict(&mut doc.trailer, strip_embedded, &mut stripped);

    let pruned = doc.prune_objects();
    doc.renumber_objects();

    let mut out = Vec::with_capacity(trimmed.len());
    doc.save_to(&mut out)
        .map_err(|e| PolyguardError::SanitizationFailed(format!("PDF save_to failed: {}", e)))?;

    notes.push(format!(
        "Rebuilt canonical PDF at 0x00 (stripped {} dangerous keys, pruned {} orphan objects)",
        stripped,
        pruned.len()
    ));
    notes.push(
        "Removed pre-header prependers, post-%%EOF trailing bytes, and rebuilt clean xref table"
            .into(),
    );

    Ok((out, notes))
}