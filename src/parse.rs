//! Stage 2: Strict structural binary parsers for JPEG, PNG, ZIP (including ZIP64), and PDF.
//!
//! Builds a complete `ByteMap` partitioning structural, metadata, entropy/pixel,
//! gap, and trailing regions with SIMD `memchr`/`memmem` and `crc32fast`.

use crate::ingest::{
    validate_image_dimensions, validate_zip_budget, validate_zip_entry_path, SafeReader,
};
use crate::types::{
    Anomaly, AnomalyKind, ByteMap, FileFormat, ParseResult, ParserMetadataFlags, PolicyConfig,
    PolyguardError, RegionType, Result, Severity,
};
use memchr::{memchr, memmem};
use std::borrow::Cow;

pub const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
pub const ZIP_LFH_SIG: &[u8; 4] = b"PK\x03\x04";
pub const ZIP_CDH_SIG: &[u8; 4] = b"PK\x01\x02";
pub const ZIP_EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
pub const ZIP64_EOCD_SIG: &[u8; 4] = b"PK\x06\x06";
pub const ZIP64_EOCD_LOC_SIG: &[u8; 4] = b"PK\x06\x07";

/// Common interface implemented by all strict binary format parsers.
pub trait FormatParser: Send + Sync {
    fn format(&self) -> FileFormat;
    fn parse(&self, data: &[u8], config: &PolicyConfig) -> Result<ParseResult>;
}

/// Detect the primary target format directly from raw bytes without trusting extensions.
pub fn detect_format(data: &[u8]) -> FileFormat {
    if data.len() >= 8 && &data[..8] == PNG_SIGNATURE {
        return FileFormat::Png;
    }
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return FileFormat::Jpeg;
    }
    if data.len() >= 5 && &data[..5] == b"%PDF-" {
        return FileFormat::Pdf;
    }
    if data.len() >= 4
        && (&data[..4] == ZIP_LFH_SIG || &data[..4] == ZIP_EOCD_SIG || &data[..4] == b"PK\x07\x08")
    {
        return FileFormat::Zip;
    }

    // ISO 32000 permits `%PDF-` within the first 1024 bytes (prepender polyglot vector).
    if memmem::find(&data[..data.len().min(1024)], b"%PDF-").is_some() {
        return FileFormat::Pdf;
    }
    // PKWARE ZIP allows prepended data before the first LFH if a valid EOCD exists.
    if find_eocd_offset(data).is_some() {
        return FileFormat::Zip;
    }
    let probe = &data[..data.len().min(4096)];
    if memmem::find(probe, PNG_SIGNATURE).is_some() {
        return FileFormat::Png;
    }
    if memmem::find(probe, b"\xFF\xD8\xFF").is_some() {
        return FileFormat::Jpeg;
    }
    FileFormat::Unknown
}

pub fn parse_auto(data: &[u8], config: &PolicyConfig) -> Result<ParseResult> {
    parse_as(data, detect_format(data), config)
}

pub fn parse_as(data: &[u8], format: FileFormat, config: &PolicyConfig) -> Result<ParseResult> {
    match format {
        FileFormat::Jpeg => JpegParser.parse(data, config),
        FileFormat::Png => PngParser.parse(data, config),
        FileFormat::Zip => ZipParser.parse(data, config),
        FileFormat::Pdf => PdfParser.parse(data, config),
        _ => Err(PolyguardError::UnsupportedFormat(format.to_string())),
    }
}

// ============================================================================
// 1. Strict JPEG Parser (ISO/IEC 10918-1)
// ============================================================================

pub struct JpegParser;

impl FormatParser for JpegParser {
    fn format(&self) -> FileFormat {
        FileFormat::Jpeg
    }

    fn parse(&self, data: &[u8], config: &PolicyConfig) -> Result<ParseResult> {
        let mut byte_map = ByteMap::new(data.len(), FileFormat::Jpeg);
        let mut anomalies = Vec::new();
        let mut flags = ParserMetadataFlags::default();

        let soi_offset = memmem::find(data, b"\xFF\xD8").ok_or_else(|| {
            PolyguardError::MalformedStructure {
                format: "JPEG",
                detail: "missing SOI (0xFFD8) marker".into(),
            }
        })?;

        if soi_offset > 0 {
            byte_map.push(0, soi_offset, RegionType::PreHeader, "Pre-SOI prepended data");
        }
        byte_map.push(soi_offset, soi_offset + 2, RegionType::Header, "SOI (0xFFD8)");

        let mut reader = SafeReader::new(data);
        reader.seek(soi_offset + 2)?;
        let (mut saw_eoi, mut saw_sof) = (false, false);

        while reader.remaining() > 0 {
            let seg_start = reader.position();
            let first = reader.read_u8()?;
            if first != 0xFF {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::StructuralMismatch,
                    severity: Severity::Medium,
                    offset: seg_start,
                    length: 1,
                    region_label: "JPEG Marker Stream".into(),
                    description: format!(
                        "expected marker prefix 0xFF at {:#x}, found {:#04x}",
                        seg_start, first
                    ),
                    score: 30,
                    whitelisted: false,
                    detected_secondary_format: None,
                });
                if let Some(rel) = memchr(0xFF, reader.remaining_slice()) {
                    let sync_pos = reader.position() + rel;
                    byte_map.push(seg_start, sync_pos, RegionType::Gap, "Unaligned inter-marker bytes");
                    reader.seek(sync_pos)?;
                    continue;
                }
                break;
            }

            let mut marker = reader.read_u8()?;
            while marker == 0xFF && reader.remaining() > 0 {
                marker = reader.read_u8()?;
            }

            match marker {
                0xD9 => {
                    let eoi_end = reader.position();
                    byte_map.push(seg_start, eoi_end, RegionType::Structure, "EOI (0xFFD9)");
                    saw_eoi = true;
                    if eoi_end < data.len() {
                        byte_map.push(eoi_end, data.len(), RegionType::TrailingData, "Post-EOI trailing data");
                    }
                    break;
                }
                0x00 | 0x01 | 0xD0..=0xD8 => {
                    byte_map.push(
                        seg_start,
                        reader.position(),
                        RegionType::Structure,
                        format!("Marker 0xFF{:02X}", marker),
                    );
                    continue;
                }
                _ => {}
            }

            if reader.remaining() < 2 {
                return Err(PolyguardError::MalformedStructure {
                    format: "JPEG",
                    detail: format!("truncated length for marker 0xFF{:02X}", marker),
                });
            }
            let seg_len = reader.read_u16_be()? as usize;
            if seg_len < 2 {
                return Err(PolyguardError::MalformedStructure {
                    format: "JPEG",
                    detail: format!("invalid marker 0xFF{:02X} length {} (< 2)", marker, seg_len),
                });
            }
            let payload = reader.read_bytes(seg_len - 2)?;
            let seg_end = reader.position();

            if matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF) {
                saw_sof = true;
                if payload.len() >= 5 {
                    let h = u16::from_be_bytes([payload[1], payload[2]]) as u32;
                    let w = u16::from_be_bytes([payload[3], payload[4]]) as u32;
                    validate_image_dimensions(w, h, config)?;
                }
                byte_map.push(seg_start, seg_end, RegionType::Structure, format!("SOF (0xFF{:02X})", marker));
            } else if marker == 0xFE {
                byte_map.push(seg_start, seg_end, RegionType::Comment, "COM (0xFFFE)");
            } else if (0xE0..=0xEF).contains(&marker) {
                let label: Cow<'static, str> = if marker == 0xE2 && payload.starts_with(b"ICC_PROFILE\0") {
                    flags.has_icc_profile = true;
                    Cow::Borrowed("APP2 (ICC_PROFILE)")
                } else if marker == 0xE1 && payload.starts_with(b"Exif\0\0") {
                    Cow::Borrowed("APP1 (EXIF)")
                } else if marker == 0xE1 && payload.starts_with(b"http://ns.adobe.com/xap/") {
                    Cow::Borrowed("APP1 (XMP)")
                } else if marker == 0xE0 && payload.starts_with(b"JFIF\0") {
                    Cow::Borrowed("APP0 (JFIF)")
                } else {
                    Cow::Owned(format!("APP{} (0xFF{:02X})", marker - 0xE0, marker))
                };
                byte_map.push(seg_start, seg_end, RegionType::Metadata, label);
            } else if marker == 0xDA {
                byte_map.push(seg_start, seg_end, RegionType::Structure, "SOS Header (0xFFDA)");
                let ecs_start = reader.position();
                let mut scan_pos = ecs_start;
                while scan_pos < data.len() {
                    let Some(rel) = memchr(0xFF, &data[scan_pos..]) else {
                        scan_pos = data.len();
                        break;
                    };
                    let ff_pos = scan_pos + rel;
                    let mut next_pos = ff_pos + 1;
                    while next_pos < data.len() && data[next_pos] == 0xFF {
                        next_pos += 1;
                    }
                    if next_pos >= data.len() {
                        scan_pos = data.len();
                        break;
                    }
                    let code = data[next_pos];
                    if code == 0x00 || (0xD0..=0xD7).contains(&code) {
                        scan_pos = next_pos + 1;
                    } else {
                        scan_pos = ff_pos;
                        break;
                    }
                }
                byte_map.push(ecs_start, scan_pos, RegionType::EntropyData, "Entropy-Coded Scan Data (ECS)");
                reader.seek(scan_pos)?;
            } else {
                byte_map.push(seg_start, seg_end, RegionType::Structure, format!("Segment 0xFF{:02X}", marker));
            }
        }

        if !saw_sof {
            anomalies.push(Anomaly {
                kind: AnomalyKind::StructuralMismatch,
                severity: Severity::Medium,
                offset: soi_offset,
                length: 2,
                region_label: "JPEG".into(),
                description: "JPEG stream does not contain a Start-Of-Frame (SOF) marker".into(),
                score: 25,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }
        if !saw_eoi {
            anomalies.push(Anomaly {
                kind: AnomalyKind::StructuralMismatch,
                severity: Severity::Medium,
                offset: data.len().saturating_sub(1),
                length: 0,
                region_label: "JPEG".into(),
                description: "missing EOI (0xFFD9) terminator".into(),
                score: 25,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }

        byte_map.finalize();
        Ok(ParseResult {
            byte_map,
            parser_anomalies: anomalies,
            metadata_flags: flags,
        })
    }
}

// ============================================================================
// 2. Strict PNG Parser (W3C / ISO/IEC 15948) with SIMD CRC32
// ============================================================================

pub struct PngParser;

impl FormatParser for PngParser {
    fn format(&self) -> FileFormat {
        FileFormat::Png
    }

    fn parse(&self, data: &[u8], config: &PolicyConfig) -> Result<ParseResult> {
        let mut byte_map = ByteMap::new(data.len(), FileFormat::Png);
        let mut anomalies = Vec::new();
        let mut flags = ParserMetadataFlags::default();

        let sig_offset = memmem::find(data, PNG_SIGNATURE).ok_or_else(|| {
            PolyguardError::MalformedStructure {
                format: "PNG",
                detail: "missing 8-byte PNG signature".into(),
            }
        })?;

        if sig_offset > 0 {
            byte_map.push(0, sig_offset, RegionType::PreHeader, "Pre-PNG prepended data");
        }
        byte_map.push(sig_offset, sig_offset + 8, RegionType::Header, "PNG Signature");

        let mut reader = SafeReader::new(data);
        reader.seek(sig_offset + 8)?;
        let (mut saw_ihdr, mut saw_iend) = (false, false);

        while reader.remaining() > 0 {
            let chunk_start = reader.position();
            if reader.remaining() < 12 {
                return Err(PolyguardError::MalformedStructure {
                    format: "PNG",
                    detail: format!("truncated chunk header at offset {:#x}", chunk_start),
                });
            }

            let chunk_len = reader.read_u32_be()? as usize;
            if chunk_len > 0x7FFF_FFFF {
                return Err(PolyguardError::MalformedStructure {
                    format: "PNG",
                    detail: format!("chunk length {chunk_len} exceeds PNG 2^31-1 specification limit"),
                });
            }
            let type_bytes = reader.read_bytes(4)?;
            let chunk_data = reader.read_bytes(chunk_len)?;
            let expected_crc = reader.read_u32_be()?;
            let chunk_end = reader.position();

            let mut hasher = crc32fast::Hasher::new();
            hasher.update(type_bytes);
            hasher.update(chunk_data);
            let actual_crc = hasher.finalize();
            let chunk_name = String::from_utf8_lossy(type_bytes).into_owned();

            if actual_crc != expected_crc {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::InvalidChecksum,
                    severity: Severity::High,
                    offset: chunk_start,
                    length: chunk_end - chunk_start,
                    region_label: format!("PNG Chunk {}", chunk_name),
                    description: format!(
                        "CRC32 mismatch in chunk '{}': expected {:#010x}, computed {:#010x}",
                        chunk_name, expected_crc, actual_crc
                    ),
                    score: 40,
                    whitelisted: false,
                    detected_secondary_format: None,
                });
            }

            match type_bytes {
                b"IHDR" => {
                    saw_ihdr = true;
                    if chunk_data.len() != 13 {
                        return Err(PolyguardError::MalformedStructure {
                            format: "PNG",
                            detail: format!("IHDR length must be 13 bytes, got {}", chunk_data.len()),
                        });
                    }
                    let w = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
                    let h = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
                    validate_image_dimensions(w, h, config)?;
                    byte_map.push(chunk_start, chunk_end, RegionType::Structure, "IHDR");
                }
                b"IDAT" => {
                    byte_map.push(chunk_start, chunk_start + 8, RegionType::Structure, "IDAT Header");
                    byte_map.push(
                        chunk_start + 8,
                        chunk_start + 8 + chunk_len,
                        RegionType::EntropyData,
                        "IDAT Compressed Pixels",
                    );
                    byte_map.push(chunk_end - 4, chunk_end, RegionType::Structure, "IDAT CRC");
                }
                b"PLTE" => byte_map.push(chunk_start, chunk_end, RegionType::Structure, "PLTE"),
                b"IEND" => {
                    saw_iend = true;
                    byte_map.push(chunk_start, chunk_end, RegionType::Structure, "IEND");
                    if chunk_end < data.len() {
                        byte_map.push(chunk_end, data.len(), RegionType::TrailingData, "Post-IEND trailing data");
                    }
                    break;
                }
                b"tEXt" | b"zTXt" | b"iTXt" => {
                    byte_map.push(
                        chunk_start,
                        chunk_end,
                        RegionType::Comment,
                        Cow::Owned(format!("PNG Text Chunk ({})", chunk_name)),
                    );
                }
                b"iCCP" => {
                    flags.has_icc_profile = true;
                    byte_map.push(chunk_start, chunk_end, RegionType::Metadata, "iCCP");
                }
                _ => {
                    byte_map.push(
                        chunk_start,
                        chunk_end,
                        RegionType::Metadata,
                        Cow::Owned(format!("PNG Chunk ({})", chunk_name)),
                    );
                }
            }
        }

        if !saw_ihdr {
            return Err(PolyguardError::MalformedStructure {
                format: "PNG",
                detail: "missing mandatory IHDR chunk".into(),
            });
        }
        if !saw_iend {
            anomalies.push(Anomaly {
                kind: AnomalyKind::StructuralMismatch,
                severity: Severity::Medium,
                offset: data.len().saturating_sub(1),
                length: 0,
                region_label: "PNG".into(),
                description: "missing IEND terminator chunk".into(),
                score: 25,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }

        byte_map.finalize();
        Ok(ParseResult {
            byte_map,
            parser_anomalies: anomalies,
            metadata_flags: flags,
        })
    }
}

// ============================================================================
// 3. Strict ZIP Parser (PKWARE APPNOTE + ZIP64)
// ============================================================================

pub struct ZipParser;

/// Locate a valid 32-bit EOCD (`PK\x05\x06`) or ZIP64 EOCD Locator (`PK\x06\x07`) + EOCD
/// within the trailing 65,557-byte search window.
pub fn find_eocd_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let search_start = data.len().saturating_sub(65_557);
    let window = &data[search_start..];
    let finder = memmem::FinderRev::new(ZIP_EOCD_SIG);

    let mut slice = window;
    while let Some(rel) = finder.rfind(slice) {
        let abs = search_start + rel;
        if abs + 22 <= data.len() {
            let cd_count = u16::from_le_bytes([data[abs + 10], data[abs + 11]]);
            let cd_size =
                u32::from_le_bytes([data[abs + 12], data[abs + 13], data[abs + 14], data[abs + 15]])
                    as usize;
            let cd_offset =
                u32::from_le_bytes([data[abs + 16], data[abs + 17], data[abs + 18], data[abs + 19]])
                    as usize;
            let comment_len = u16::from_le_bytes([data[abs + 20], data[abs + 21]]) as usize;
            let eocd_end = abs.saturating_add(22).saturating_add(comment_len);

            if eocd_end <= data.len() {
                if cd_count == 0 && cd_size == 0 {
                    return Some(abs);
                }
                if find_zip64_eocd(data, abs).is_some() {
                    return Some(abs);
                }
                if cd_offset + 4 <= data.len() && &data[cd_offset..cd_offset + 4] == ZIP_CDH_SIG {
                    return Some(abs);
                }
                if cd_offset < abs && cd_size <= abs {
                    let implied_base = abs.saturating_sub(cd_size).saturating_sub(cd_offset);
                    let shifted_cd = implied_base.saturating_add(cd_offset);
                    if shifted_cd + 4 <= data.len()
                        && &data[shifted_cd..shifted_cd + 4] == ZIP_CDH_SIG
                    {
                        return Some(abs);
                    }
                }
            }
        }
        slice = &window[..rel];
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct Zip64EocdInfo {
    locator_offset: usize,
    record_offset: usize,
    record_end: usize,
    entry_count: usize,
    cd_size: usize,
    cd_offset: usize,
}

/// Locate and validate the 20-byte ZIP64 EOCD Locator (`PK\x06\x07`) immediately preceding
/// `eocd_offset` and its referenced ZIP64 EOCD Record (`PK\x06\x06`).
fn find_zip64_eocd(data: &[u8], eocd_offset: usize) -> Option<Zip64EocdInfo> {
    if eocd_offset < 20 {
        return None;
    }
    let loc_offset = eocd_offset - 20;
    if &data[loc_offset..loc_offset + 4] != ZIP64_EOCD_LOC_SIG {
        return None;
    }

    let z64_offset_u64 = u64::from_le_bytes(data[loc_offset + 8..loc_offset + 16].try_into().ok()?);
    let z64_offset = usize::try_from(z64_offset_u64).ok()?;
    if z64_offset.checked_add(56)? > loc_offset {
        return None;
    }
    if &data[z64_offset..z64_offset + 4] != ZIP64_EOCD_SIG {
        return None;
    }

    let z64_body_size_u64 =
        u64::from_le_bytes(data[z64_offset + 4..z64_offset + 12].try_into().ok()?);
    let z64_body_size = usize::try_from(z64_body_size_u64).ok()?;
    let record_end = z64_offset.checked_add(12)?.checked_add(z64_body_size)?;
    if record_end > loc_offset {
        return None;
    }

    let entry_count = usize::try_from(u64::from_le_bytes(
        data[z64_offset + 32..z64_offset + 40].try_into().ok()?,
    ))
    .ok()?;
    let cd_size = usize::try_from(u64::from_le_bytes(
        data[z64_offset + 40..z64_offset + 48].try_into().ok()?,
    ))
    .ok()?;
    let cd_offset = usize::try_from(u64::from_le_bytes(
        data[z64_offset + 48..z64_offset + 56].try_into().ok()?,
    ))
    .ok()?;

    if entry_count == 0 && cd_size == 0 {
        return Some(Zip64EocdInfo {
            locator_offset: loc_offset,
            record_offset: z64_offset,
            record_end,
            entry_count,
            cd_size,
            cd_offset,
        });
    }
    if cd_offset.checked_add(4)? <= data.len() && &data[cd_offset..cd_offset + 4] == ZIP_CDH_SIG {
        return Some(Zip64EocdInfo {
            locator_offset: loc_offset,
            record_offset: z64_offset,
            record_end,
            entry_count,
            cd_size,
            cd_offset,
        });
    }
    None
}

/// Extract 64-bit sizes/offsets from the ZIP64 Extended Information Extra Field (`0x0001`).
fn parse_zip64_extra_field(
    extra: &[u8],
    need_uncomp: bool,
    need_comp: bool,
    need_offset: bool,
) -> (Option<u64>, Option<u64>, Option<usize>) {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let data_size = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        pos += 4;
        if pos + data_size > extra.len() {
            break;
        }
        if header_id == 0x0001 {
            let field = &extra[pos..pos + data_size];
            let mut fpos = 0usize;
            let uncomp = if need_uncomp && fpos + 8 <= field.len() {
                let v = u64::from_le_bytes(field[fpos..fpos + 8].try_into().unwrap());
                fpos += 8;
                Some(v)
            } else {
                None
            };
            let comp = if need_comp && fpos + 8 <= field.len() {
                let v = u64::from_le_bytes(field[fpos..fpos + 8].try_into().unwrap());
                fpos += 8;
                Some(v)
            } else {
                None
            };
            let offset = if need_offset && fpos + 8 <= field.len() {
                let v = u64::from_le_bytes(field[fpos..fpos + 8].try_into().unwrap());
                usize::try_from(v).ok()
            } else {
                None
            };
            return (uncomp, comp, offset);
        }
        pos += data_size;
    }
    (None, None, None)
}

impl FormatParser for ZipParser {
    fn format(&self) -> FileFormat {
        FileFormat::Zip
    }

    fn parse(&self, data: &[u8], config: &PolicyConfig) -> Result<ParseResult> {
        let mut byte_map = ByteMap::new(data.len(), FileFormat::Zip);
        let mut anomalies = Vec::new();
        let mut flags = ParserMetadataFlags::default();

        let eocd_offset = find_eocd_offset(data).ok_or_else(|| {
            PolyguardError::MalformedStructure {
                format: "ZIP",
                detail: "missing valid End of Central Directory (PK\\x05\\x06)".into(),
            }
        })?;

        let reader = SafeReader::new(data);
        let entry_count_16 = reader.read_u16_le_at(eocd_offset + 10)?;
        let cd_size_32 = reader.read_u32_le_at(eocd_offset + 12)?;
        let cd_offset_32 = reader.read_u32_le_at(eocd_offset + 16)?;
        let comment_len = reader.read_u16_le_at(eocd_offset + 20)? as usize;

        // Resolve ZIP64 EOCD Locator + Record if present.
        let zip64 = find_zip64_eocd(data, eocd_offset);
        let (entry_count, cd_size, cd_offset_raw, cd_end_limit) = if let Some(z64) = zip64 {
            byte_map.push(
                z64.record_offset,
                z64.record_end,
                RegionType::Structure,
                "ZIP64 EOCD Record (PK\\x06\\x06)",
            );
            byte_map.push(
                z64.locator_offset,
                eocd_offset,
                RegionType::Structure,
                "ZIP64 EOCD Locator (PK\\x06\\x07)",
            );
            let entries = if entry_count_16 == u16::MAX {
                z64.entry_count
            } else {
                entry_count_16 as usize
            };
            let size = if cd_size_32 == u32::MAX {
                z64.cd_size
            } else {
                cd_size_32 as usize
            };
            let offset = if cd_offset_32 == u32::MAX {
                z64.cd_offset
            } else {
                cd_offset_32 as usize
            };
            (entries, size, offset, z64.record_offset)
        } else {
            (
                entry_count_16 as usize,
                cd_size_32 as usize,
                cd_offset_32 as usize,
                eocd_offset,
            )
        };

        if entry_count > config.max_zip_entries {
            return Err(PolyguardError::ZipBomb {
                uncompressed: 0,
                compressed: data.len() as u64,
                ratio: f64::INFINITY,
            });
        }

        let (base_shift, cd_start) = if entry_count == 0 {
            (0usize, cd_offset_raw.min(cd_end_limit))
        } else if cd_offset_raw + 4 <= data.len()
            && &data[cd_offset_raw..cd_offset_raw + 4] == ZIP_CDH_SIG
        {
            (0usize, cd_offset_raw)
        } else {
            let implied = cd_end_limit
                .saturating_sub(cd_size)
                .saturating_sub(cd_offset_raw);
            let shifted = implied.saturating_add(cd_offset_raw);
            if shifted + 4 <= data.len() && &data[shifted..shifted + 4] == ZIP_CDH_SIG {
                (implied, shifted)
            } else {
                return Err(PolyguardError::MalformedStructure {
                    format: "ZIP",
                    detail: "Central Directory offset does not point to PK\\x01\\x02".into(),
                });
            }
        };

        let eocd_struct_end = eocd_offset + 22;
        byte_map.push(
            eocd_offset,
            eocd_struct_end,
            RegionType::Structure,
            "EOCD (PK\\x05\\x06)",
        );
        let eocd_total_end = eocd_struct_end.saturating_add(comment_len).min(data.len());
        if comment_len > 0 {
            byte_map.push(
                eocd_struct_end,
                eocd_total_end,
                RegionType::Comment,
                "ZIP Archive Comment",
            );
        }
        if eocd_total_end < data.len() {
            byte_map.push(
                eocd_total_end,
                data.len(),
                RegionType::TrailingData,
                "Post-EOCD trailing data",
            );
        }

        let mut cd_cursor = SafeReader::new(data);
        cd_cursor.seek(cd_start)?;
        let (mut total_comp, mut total_uncomp) = (0u64, 0u64);
        let mut min_lfh_offset: Option<usize> = None;

        for idx in 0..entry_count {
            let cdh_start = cd_cursor.position();
            if cd_cursor.read_bytes(4)? != ZIP_CDH_SIG {
                return Err(PolyguardError::MalformedStructure {
                    format: "ZIP",
                    detail: format!(
                        "invalid Central Directory signature at entry {} (offset {:#x})",
                        idx, cdh_start
                    ),
                });
            }
            cd_cursor.skip(4)?; // version made by + version needed
            let gp_flags = cd_cursor.read_u16_le()?;
            cd_cursor.skip(10)?; // method + time + date + crc32
            let comp_32 = cd_cursor.read_u32_le()?;
            let uncomp_32 = cd_cursor.read_u32_le()?;
            let name_len = cd_cursor.read_u16_le()? as usize;
            let extra_len = cd_cursor.read_u16_le()? as usize;
            let entry_comment_len = cd_cursor.read_u16_le()? as usize;
            cd_cursor.skip(8)?; // disk_start + int_attr + ext_attr
            let lfh_rel_32 = cd_cursor.read_u32_le()?;

            let entry_name = String::from_utf8_lossy(cd_cursor.read_bytes(name_len)?).into_owned();
            let extra_bytes = cd_cursor.read_bytes(extra_len)?;
            let comment_start = cd_cursor.position();
            cd_cursor.skip(entry_comment_len)?;
            let cdh_end = cd_cursor.position();

            // Resolve 64-bit ZIP64 sizes/offsets if sentinel 0xFFFF_FFFF values are present.
            let (z64_uncomp, z64_comp, z64_off) = parse_zip64_extra_field(
                extra_bytes,
                uncomp_32 == u32::MAX,
                comp_32 == u32::MAX,
                lfh_rel_32 == u32::MAX,
            );
            let comp_size = z64_comp.unwrap_or(comp_32 as u64);
            let uncomp_size = z64_uncomp.unwrap_or(uncomp_32 as u64);
            let lfh_rel_offset = z64_off.unwrap_or(lfh_rel_32 as usize);

            byte_map.push(
                cdh_start,
                comment_start,
                RegionType::Structure,
                Cow::Owned(format!("CD Entry #{} ({})", idx, entry_name)),
            );
            if entry_comment_len > 0 {
                byte_map.push(
                    comment_start,
                    cdh_end,
                    RegionType::Comment,
                    Cow::Owned(format!("CD Comment ({})", entry_name)),
                );
            }

            if let Err(PolyguardError::ZipSlip { path }) = validate_zip_entry_path(&entry_name) {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::PathTraversal,
                    severity: Severity::Critical,
                    offset: cdh_start,
                    length: cdh_end - cdh_start,
                    region_label: format!("ZIP Entry {}", path),
                    description: format!("Zip Slip path traversal detected: '{}'", path),
                    score: 100,
                    whitelisted: false,
                    detected_secondary_format: None,
                });
            }

            flags.zip_entry_names.push(entry_name.clone());
            total_comp = total_comp.saturating_add(comp_size);
            total_uncomp = total_uncomp.saturating_add(uncomp_size);
            validate_zip_budget(total_uncomp, total_comp, entry_count, config)?;

            let lfh_offset = base_shift.saturating_add(lfh_rel_offset);
            min_lfh_offset = Some(min_lfh_offset.map_or(lfh_offset, |m| m.min(lfh_offset)));

            let mut lfh = SafeReader::new(data);
            lfh.seek(lfh_offset)?;
            if lfh.read_bytes(4)? != ZIP_LFH_SIG {
                return Err(PolyguardError::MalformedStructure {
                    format: "ZIP",
                    detail: format!("invalid LFH signature for '{}' at {:#x}", entry_name, lfh_offset),
                });
            }
            lfh.skip(14)?;
            let lfh_comp_32 = lfh.read_u32_le()?;
            let lfh_uncomp_32 = lfh.read_u32_le()?;
            let lfh_name_len = lfh.read_u16_le()? as usize;
            let lfh_extra_len = lfh.read_u16_le()? as usize;
            lfh.skip(lfh_name_len)?;
            let lfh_extra_start = lfh.position();
            let lfh_extra_bytes = lfh.read_bytes(lfh_extra_len)?;
            let payload_start = lfh.position();

            let (_, lfh_z64_comp, _) = parse_zip64_extra_field(
                lfh_extra_bytes,
                lfh_uncomp_32 == u32::MAX,
                lfh_comp_32 == u32::MAX,
                false,
            );
            let lfh_comp_size = lfh_z64_comp.unwrap_or(lfh_comp_32 as u64);

            if (gp_flags & 0x0008) == 0 && lfh_comp_size != comp_size {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::StructuralMismatch,
                    severity: Severity::High,
                    offset: lfh_offset,
                    length: payload_start - lfh_offset,
                    region_label: format!("LFH ({})", entry_name),
                    description: format!(
                        "compressed size mismatch between LFH ({}) and CD ({})",
                        lfh_comp_size, comp_size
                    ),
                    score: 45,
                    whitelisted: false,
                    detected_secondary_format: None,
                });
            }

            byte_map.push(
                lfh_offset,
                lfh_extra_start,
                if lfh_offset == 0 {
                    RegionType::Header
                } else {
                    RegionType::Structure
                },
                Cow::Owned(format!("LFH ({})", entry_name)),
            );
            if lfh_extra_len > 0 {
                byte_map.push(
                    lfh_extra_start,
                    payload_start,
                    RegionType::Metadata,
                    Cow::Owned(format!("LFH Extra Field ({})", entry_name)),
                );
            }

            let comp_usize = usize::try_from(comp_size).map_err(|_| PolyguardError::OutOfBounds {
                offset: payload_start,
                needed: usize::MAX,
                len: data.len(),
            })?;
            let payload_end = payload_start
                .checked_add(comp_usize)
                .ok_or(PolyguardError::OutOfBounds {
                    offset: payload_start,
                    needed: comp_usize,
                    len: data.len(),
                })?;
            if payload_end > data.len() {
                return Err(PolyguardError::MalformedStructure {
                    format: "ZIP",
                    detail: format!("entry '{}' payload exceeds archive size", entry_name),
                });
            }
            byte_map.push(
                payload_start,
                payload_end,
                RegionType::EntropyData,
                Cow::Owned(format!("ZIP Entry Payload ({})", entry_name)),
            );

            if (gp_flags & 0x0008) != 0 && payload_end + 12 <= cd_start {
                let dd_len = if payload_end + 16 <= cd_start
                    && &data[payload_end..payload_end + 4] == b"PK\x07\x08"
                {
                    if zip64.is_some() && payload_end + 24 <= cd_start {
                        24
                    } else {
                        16
                    }
                } else if zip64.is_some() && payload_end + 20 <= cd_start {
                    20
                } else {
                    12
                };
                byte_map.push(
                    payload_end,
                    payload_end + dd_len,
                    RegionType::Structure,
                    "ZIP Data Descriptor",
                );
            }
        }

        if let Some(first_lfh) = min_lfh_offset {
            if first_lfh > 0 {
                byte_map.push(
                    0,
                    first_lfh,
                    RegionType::PreHeader,
                    "Pre-LFH prepended data (ZIP prepender)",
                );
            }
        }

        let has_ct = flags
            .zip_entry_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("[Content_Types].xml"));
        let has_rels = flags
            .zip_entry_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("_rels/.rels"));
        flags.is_ooxml = has_ct && has_rels;

        byte_map.finalize();
        Ok(ParseResult {
            byte_map,
            parser_anomalies: anomalies,
            metadata_flags: flags,
        })
    }
}

// ============================================================================
// 4. Strict PDF Parser (ISO 32000)
// ============================================================================

pub struct PdfParser;

const DANGEROUS_PDF_KEYWORDS: &[(&[u8], &str, Severity, u32)] = &[
    (b"/JavaScript", "Embedded JavaScript action (/JavaScript)", Severity::Critical, 80),
    (b"/JS", "Embedded JavaScript shorthand (/JS)", Severity::High, 65),
    (b"/OpenAction", "Automatic document open action (/OpenAction)", Severity::High, 55),
    (b"/AA", "Additional automatic trigger action (/AA)", Severity::Medium, 40),
    (b"/Launch", "External application launch action (/Launch)", Severity::Critical, 90),
    (b"/RichMedia", "Embedded RichMedia/Flash payload (/RichMedia)", Severity::High, 60),
    (b"/XFA", "Dynamic XFA form script container (/XFA)", Severity::High, 55),
    (b"/SubmitForm", "External form data exfiltration (/SubmitForm)", Severity::Medium, 40),
    (b"/EmbeddedFile", "Embedded file stream (/EmbeddedFile)", Severity::Medium, 35),
    (b"/EmbeddedFiles", "Embedded files name tree (/EmbeddedFiles)", Severity::Medium, 35),
];

impl FormatParser for PdfParser {
    fn format(&self) -> FileFormat {
        FileFormat::Pdf
    }

    fn parse(&self, data: &[u8], _config: &PolicyConfig) -> Result<ParseResult> {
        let mut byte_map = ByteMap::new(data.len(), FileFormat::Pdf);
        let mut anomalies = Vec::new();
        let mut flags = ParserMetadataFlags::default();

        let pdf_start = memmem::find(&data[..data.len().min(1024)], b"%PDF-").ok_or_else(|| {
            PolyguardError::MalformedStructure {
                format: "PDF",
                detail: "missing %PDF- header within first 1024 bytes".into(),
            }
        })?;

        if pdf_start > 0 {
            byte_map.push(
                0,
                pdf_start,
                RegionType::PreHeader,
                "Pre-PDF prepended data (before %PDF-)",
            );
        }

        let header_end = memchr(b'\n', &data[pdf_start..])
            .map(|rel| pdf_start + rel + 1)
            .unwrap_or((pdf_start + 8).min(data.len()));
        byte_map.push(pdf_start, header_end, RegionType::Header, "PDF Header (%PDF-)");

        let eof_positions: Vec<usize> = memmem::Finder::new(b"%%EOF")
            .find_iter(&data[header_end..])
            .map(|rel| header_end + rel)
            .collect();

        if eof_positions.is_empty() {
            anomalies.push(Anomaly {
                kind: AnomalyKind::StructuralMismatch,
                severity: Severity::Medium,
                offset: data.len().saturating_sub(1),
                length: 0,
                region_label: "PDF".into(),
                description: "missing %%EOF terminator".into(),
                score: 30,
                whitelisted: false,
                detected_secondary_format: None,
            });
        } else if eof_positions.len() > 1 {
            flags.has_pdf_incremental_updates = true;
            anomalies.push(Anomaly {
                kind: AnomalyKind::StructuralMismatch,
                severity: Severity::Low,
                offset: eof_positions[0],
                length: 5,
                region_label: "PDF Revisions".into(),
                description: format!(
                    "PDF contains {} %%EOF markers (incremental updates detected)",
                    eof_positions.len()
                ),
                score: 15,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }

        let pdf_body_end = if let Some(&last_eof) = eof_positions.last() {
            let mut end = (last_eof + 5).min(data.len());
            while end < data.len() && (data[end] == b'\r' || data[end] == b'\n') {
                end += 1;
            }
            if end < data.len() {
                byte_map.push(end, data.len(), RegionType::TrailingData, "Post-%%EOF trailing data");
            }
            end
        } else {
            data.len()
        };

        let body = &data[header_end..pdf_body_end];
        let stream_finder = memmem::Finder::new(b"stream");
        let endstream_finder = memmem::Finder::new(b"endstream");

        let mut cursor = 0usize;
        while cursor < body.len() {
            let Some(rel_s) = stream_finder.find(&body[cursor..]) else {
                break;
            };
            let s_pos = cursor + rel_s;
            if s_pos >= 3 && &body[s_pos - 3..s_pos] == b"end" {
                cursor = s_pos + 6;
                continue;
            }
            let after_kw = s_pos + 6;
            let stream_data_rel = if body.get(after_kw..after_kw + 2) == Some(b"\r\n") {
                after_kw + 2
            } else if body.get(after_kw) == Some(&b'\n') {
                after_kw + 1
            } else {
                cursor = after_kw;
                continue;
            };

            let Some(rel_end) = endstream_finder.find(&body[stream_data_rel..]) else {
                break;
            };
            let endstream_rel = stream_data_rel + rel_end;
            if s_pos > cursor {
                byte_map.push(
                    header_end + cursor,
                    header_end + stream_data_rel,
                    RegionType::Structure,
                    "PDF Objects / Dictionary",
                );
            }
            byte_map.push(
                header_end + stream_data_rel,
                header_end + endstream_rel,
                RegionType::EntropyData,
                "PDF Stream Payload",
            );
            let after_endstream = endstream_rel + 9;
            byte_map.push(
                header_end + endstream_rel,
                header_end + after_endstream,
                RegionType::Structure,
                "PDF endstream",
            );
            cursor = after_endstream;
        }

        if header_end + cursor < pdf_body_end {
            let tail_start = header_end + cursor;
            if let Some(xref_rel) = memmem::find(&data[tail_start..pdf_body_end], b"xref") {
                if xref_rel > 0 {
                    byte_map.push(tail_start, tail_start + xref_rel, RegionType::Structure, "PDF Objects");
                }
                byte_map.push(
                    tail_start + xref_rel,
                    pdf_body_end,
                    RegionType::Structure,
                    "PDF XRef & Trailer",
                );
            } else {
                byte_map.push(
                    tail_start,
                    pdf_body_end,
                    RegionType::Structure,
                    "PDF Trailer / XRef Stream",
                );
            }
        }

        if memmem::find(&data[pdf_start..pdf_body_end], b"startxref").is_none() {
            anomalies.push(Anomaly {
                kind: AnomalyKind::StructuralMismatch,
                severity: Severity::Medium,
                offset: pdf_start,
                length: pdf_body_end.saturating_sub(pdf_start).min(64),
                region_label: "PDF XRef".into(),
                description: "missing startxref pointer in PDF trailer".into(),
                score: 30,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }

        for region in byte_map.scannable_regions() {
            if !matches!(region.region_type, RegionType::Structure | RegionType::Metadata) {
                continue;
            }
            let slice = &data[region.start..region.end];
            for &(kw, desc, severity, score) in DANGEROUS_PDF_KEYWORDS {
                if let Some(rel) = memmem::find(slice, kw) {
                    let after = rel + kw.len();
                    if slice.get(after).is_none_or(|b| !b.is_ascii_alphanumeric()) {
                        if kw == b"/EmbeddedFile" || kw == b"/EmbeddedFiles" {
                            flags.has_pdf_embedded_files = true;
                        }
                        anomalies.push(Anomaly {
                            kind: AnomalyKind::DangerousKeyword,
                            severity,
                            offset: region.start + rel,
                            length: kw.len(),
                            region_label: region.label.to_string(),
                            description: desc.to_string(),
                            score,
                            whitelisted: false,
                            detected_secondary_format: None,
                        });
                    }
                }
            }
        }

        byte_map.finalize();
        Ok(ParseResult {
            byte_map,
            parser_anomalies: anomalies,
            metadata_flags: flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_chunk(ty: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(ty);
        out.extend_from_slice(payload);
        let mut h = crc32fast::Hasher::new();
        h.update(ty);
        h.update(payload);
        out.extend_from_slice(&h.finalize().to_be_bytes());
        out
    }

    #[test]
    fn blocks_pixel_flood_png() {
        let mut png = PNG_SIGNATURE.to_vec();
        let mut ihdr = [0u8; 13];
        ihdr[0..4].copy_from_slice(&100_000u32.to_be_bytes());
        ihdr[4..8].copy_from_slice(&100_000u32.to_be_bytes());
        ihdr[8] = 8;
        ihdr[9] = 2;
        png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
        png.extend_from_slice(&png_chunk(b"IEND", &[]));

        let err = PngParser.parse(&png, &PolicyConfig::default()).unwrap_err();
        assert!(matches!(err, PolyguardError::PixelFlood { .. }));
    }

    #[test]
    fn parses_jpeg_and_isolates_trailing_bytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xFF, 0xD8]);
        buf.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x07, b'J', b'F', b'I', b'F', 0x00]);
        buf.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00]);
        buf.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        buf.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        buf.extend_from_slice(b"PK\x03\x04trailing");

        let res = JpegParser.parse(&buf, &PolicyConfig::default()).unwrap();
        assert_eq!(res.byte_map.bytes_of_type(RegionType::EntropyData), 2);
        assert_eq!(res.byte_map.bytes_of_type(RegionType::TrailingData), 12);
    }
}