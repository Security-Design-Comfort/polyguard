//! Stage 1: Hybrid zero-copy memory-mapped I/O, overflow-safe binary cursor, and DoS guardrails.

use crate::types::{PolicyConfig, PolyguardError, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;

/// Hardware-optimal input container:
/// - `< mmap_threshold_bytes`: pre-sized heap `Vec<u8>` to avoid `mmap`/TLB syscall overhead.
/// - `>= mmap_threshold_bytes`: zero-copy OS page-cache `Mmap`.
pub enum InputBuffer {
    Owned(Vec<u8>),
    Mapped(Mmap),
}

impl InputBuffer {
    pub fn from_file(path: &Path, config: &PolicyConfig) -> Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();

        if len == 0 {
            return Err(PolyguardError::EmptyFile);
        }
        if len > config.max_file_size_bytes {
            return Err(PolyguardError::FileTooLarge {
                size: len,
                max: config.max_file_size_bytes,
            });
        }

        if len >= config.mmap_threshold_bytes {
            // SAFETY: File must not be concurrently truncated while mapped (see `notice.md`).
            let mmap = unsafe { Mmap::map(&file)? };
            Ok(Self::Mapped(mmap))
        } else {
            let mut buf = Vec::with_capacity(len as usize);
            file.take(config.max_file_size_bytes)
                .read_to_end(&mut buf)?;
            Ok(Self::Owned(buf))
        }
    }

    #[inline]
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self::Owned(data)
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(v) => v.as_slice(),
            Self::Mapped(m) => m.as_ref(),
        }
    }
}

impl Deref for InputBuffer {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// Zero-copy, strictly bounds-checked cursor using `checked_add` on every offset operation.
#[derive(Debug, Clone, Copy)]
pub struct SafeReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SafeReader<'a> {
    #[inline(always)]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline(always)]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[inline(always)]
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    #[inline(always)]
    pub fn seek(&mut self, offset: usize) -> Result<()> {
        if offset > self.data.len() {
            return Err(PolyguardError::OutOfBounds {
                offset,
                needed: 0,
                len: self.data.len(),
            });
        }
        self.pos = offset;
        Ok(())
    }

    #[inline(always)]
    pub fn skip(&mut self, count: usize) -> Result<()> {
        let next = self
            .pos
            .checked_add(count)
            .ok_or(PolyguardError::OutOfBounds {
                offset: self.pos,
                needed: count,
                len: self.data.len(),
            })?;
        if next > self.data.len() {
            return Err(PolyguardError::OutOfBounds {
                offset: self.pos,
                needed: count,
                len: self.data.len(),
            });
        }
        self.pos = next;
        Ok(())
    }

    #[inline(always)]
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or(PolyguardError::OutOfBounds {
                offset: self.pos,
                needed: count,
                len: self.data.len(),
            })?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(PolyguardError::OutOfBounds {
                offset: self.pos,
                needed: count,
                len: self.data.len(),
            })?;
        self.pos = end;
        Ok(slice)
    }

    #[inline(always)]
    pub fn slice_at(&self, offset: usize, count: usize) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(count)
            .ok_or(PolyguardError::OutOfBounds {
                offset,
                needed: count,
                len: self.data.len(),
            })?;
        self.data
            .get(offset..end)
            .ok_or(PolyguardError::OutOfBounds {
                offset,
                needed: count,
                len: self.data.len(),
            })
    }

    #[inline(always)]
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    #[inline(always)]
    pub fn read_u16_be(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    #[inline(always)]
    pub fn read_u32_be(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline(always)]
    pub fn read_u16_le(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline(always)]
    pub fn read_u32_le(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline(always)]
    pub fn read_u16_le_at(&self, offset: usize) -> Result<u16> {
        let b = self.slice_at(offset, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline(always)]
    pub fn read_u32_le_at(&self, offset: usize) -> Result<u32> {
        let b = self.slice_at(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

// ============================================================================
// Stage 1 Resource & Security Guardrails
// ============================================================================

#[inline]
pub fn validate_input_size(data: &[u8], config: &PolicyConfig) -> Result<()> {
    if data.is_empty() {
        return Err(PolyguardError::EmptyFile);
    }
    let size = data.len() as u64;
    if size > config.max_file_size_bytes {
        return Err(PolyguardError::FileTooLarge {
            size,
            max: config.max_file_size_bytes,
        });
    }
    Ok(())
}

#[inline]
pub fn validate_image_dimensions(width: u32, height: u32, config: &PolicyConfig) -> Result<()> {
    if width == 0 || height == 0 {
        return Err(PolyguardError::MalformedStructure {
            format: "IMAGE",
            detail: format!("invalid zero dimension: {}x{}", width, height),
        });
    }
    let total_pixels = (width as u64).saturating_mul(height as u64);
    if width > config.max_image_width
        || height > config.max_image_height
        || total_pixels > config.max_image_pixels
    {
        return Err(PolyguardError::PixelFlood {
            width,
            height,
            max_pixels: config.max_image_pixels,
        });
    }
    if total_pixels.saturating_mul(4) > config.max_decode_memory_bytes {
        return Err(PolyguardError::PixelFlood {
            width,
            height,
            max_pixels: config.max_decode_memory_bytes / 4,
        });
    }
    Ok(())
}

#[inline]
pub fn validate_zip_budget(
    total_uncompressed: u64,
    total_compressed: u64,
    entry_count: usize,
    config: &PolicyConfig,
) -> Result<()> {
    if entry_count > config.max_zip_entries {
        return Err(PolyguardError::ZipBomb {
            uncompressed: total_uncompressed,
            compressed: total_compressed,
            ratio: f64::INFINITY,
        });
    }
    if total_uncompressed > config.max_zip_uncompressed_bytes {
        let ratio = if total_compressed > 0 {
            total_uncompressed as f64 / total_compressed as f64
        } else {
            total_uncompressed as f64
        };
        return Err(PolyguardError::ZipBomb {
            uncompressed: total_uncompressed,
            compressed: total_compressed,
            ratio,
        });
    }
    if total_uncompressed >= 1024 * 1024 && total_compressed > 0 {
        let ratio = total_uncompressed as f64 / total_compressed as f64;
        if ratio > config.max_zip_compression_ratio {
            return Err(PolyguardError::ZipBomb {
                uncompressed: total_uncompressed,
                compressed: total_compressed,
                ratio,
            });
        }
    }
    Ok(())
}

pub fn validate_zip_entry_path(raw_name: &str) -> Result<()> {
    if raw_name.is_empty()
        || raw_name.contains('\0')
        || raw_name.starts_with('/')
        || raw_name.starts_with('\\')
        || (raw_name.len() >= 2 && raw_name.as_bytes()[1] == b':')
    {
        return Err(PolyguardError::ZipSlip {
            path: raw_name.to_string(),
        });
    }
    for segment in raw_name.split(['/', '\\']) {
        if segment == ".." {
            return Err(PolyguardError::ZipSlip {
                path: raw_name.to_string(),
            });
        }
    }
    Ok(())
}
