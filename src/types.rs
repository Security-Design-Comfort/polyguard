//! Unified domain models: errors, policy configuration, structural ByteMap, and analysis reports.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Unified result alias across `polyguard`.
pub type Result<T> = std::result::Result<T, PolyguardError>;

/// Exhaustive error taxonomy covering ingestion guardrails, binary parsing, policy, and CDR.
#[derive(Debug, Error)]
pub enum PolyguardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file size ({size} bytes) exceeds maximum allowed limit ({max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    #[error("input file is empty (0 bytes)")]
    EmptyFile,

    #[error("unsupported or unrecognized file format: {0}")]
    UnsupportedFormat(String),

    #[error("out-of-bounds read at offset {offset:#x} (needed {needed} bytes, total {len} bytes)")]
    OutOfBounds {
        offset: usize,
        needed: usize,
        len: usize,
    },

    #[error("malformed {format} structure: {detail}")]
    MalformedStructure {
        format: &'static str,
        detail: String,
    },

    #[error("pixel flood detected: {width}x{height} exceeds maximum {max_pixels} pixels")]
    PixelFlood {
        width: u32,
        height: u32,
        max_pixels: u64,
    },

    #[error("zip bomb detected: uncompressed={uncompressed} bytes, compressed={compressed} bytes (ratio {ratio:.2}x)")]
    ZipBomb {
        uncompressed: u64,
        compressed: u64,
        ratio: f64,
    },

    #[error("zip slip path traversal detected in entry: {path}")]
    ZipSlip { path: String },

    #[error("policy configuration error: {0}")]
    ConfigError(String),

    #[error("sanitization failed: {0}")]
    SanitizationFailed(String),

    #[error("isolated CDR worker timed out after {timeout_ms} ms")]
    IsolationTimeout { timeout_ms: u64 },

    #[error("isolated CDR worker failure: {0}")]
    IsolationFailed(String),
}

// ============================================================================
// Policy Configuration
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Strictness {
    Strict,
    #[default]
    Balanced,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WhitelistConfig {
    pub allow_ooxml: bool,
    pub allow_standard_icc_profile: bool,
    pub allow_pdf_incremental_updates: bool,
    pub allow_pdf_embedded_files: bool,
    pub allowed_png_ancillary_chunks: Vec<String>,
}

impl Default for WhitelistConfig {
    fn default() -> Self {
        Self {
            allow_ooxml: true,
            allow_standard_icc_profile: true,
            allow_pdf_incremental_updates: false,
            allow_pdf_embedded_files: false,
            allowed_png_ancillary_chunks: vec![
                "sRGB".into(),
                "gAMA".into(),
                "cHRM".into(),
                "pHYs".into(),
                "iCCP".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub strictness: Strictness,
    pub max_file_size_bytes: u64,
    pub allow_mmap: bool,
    pub mmap_threshold_bytes: u64,
    pub max_image_width: u32,
    pub max_image_height: u32,
    pub max_image_pixels: u64,
    pub max_decode_memory_bytes: u64,
    pub max_zip_entries: usize,
    pub max_zip_uncompressed_bytes: u64,
    pub max_zip_compression_ratio: f64,
    pub max_metadata_region_bytes: usize,
    pub enable_lsb_detection: bool,
    pub lsb_chi_square_threshold: f64,
    pub jpeg_reencode_quality: u8,
    pub strip_lsb_on_sanitize: bool,
    pub pdf_fallback_tool: Option<String>,
    pub enable_process_isolation: bool,
    pub worker_timeout_ms: u64,
    pub worker_memory_limit_bytes: u64,
    pub whitelist: WhitelistConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            strictness: Strictness::Balanced,
            max_file_size_bytes: 100 * 1024 * 1024,
            allow_mmap: true,
            mmap_threshold_bytes: 64 * 1024,
            max_image_width: 16_384,
            max_image_height: 16_384,
            max_image_pixels: 100_000_000,
            max_decode_memory_bytes: 256 * 1024 * 1024,
            max_zip_entries: 10_000,
            max_zip_uncompressed_bytes: 512 * 1024 * 1024,
            max_zip_compression_ratio: 100.0,
            max_metadata_region_bytes: 64 * 1024,
            enable_lsb_detection: true,
            lsb_chi_square_threshold: 0.99,
            jpeg_reencode_quality: 92,
            strip_lsb_on_sanitize: true,
            pdf_fallback_tool: None,
            enable_process_isolation: true,
            worker_timeout_ms: 15_000,
            worker_memory_limit_bytes: 512 * 1024 * 1024,
            whitelist: WhitelistConfig::default(),
        }
    }
}

impl PolicyConfig {
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            PolyguardError::ConfigError(format!("failed to read {}: {}", path.display(), e))
        })?;
        Self::from_toml_str(&content)
    }

    pub fn from_toml_str(input: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(input)
            .map_err(|e| PolyguardError::ConfigError(format!("invalid TOML policy: {}", e)))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_file_size_bytes == 0 {
            return Err(PolyguardError::ConfigError(
                "max_file_size_bytes must be > 0".into(),
            ));
        }
        if self.jpeg_reencode_quality == 0 || self.jpeg_reencode_quality > 100 {
            return Err(PolyguardError::ConfigError(
                "jpeg_reencode_quality must be in 1..=100".into(),
            ));
        }
        if self.max_zip_compression_ratio < 1.0 {
            return Err(PolyguardError::ConfigError(
                "max_zip_compression_ratio must be >= 1.0".into(),
            ));
        }
        if !(0.0 < self.lsb_chi_square_threshold && self.lsb_chi_square_threshold <= 1.0) {
            return Err(PolyguardError::ConfigError(
                "lsb_chi_square_threshold must be in (0.0, 1.0]".into(),
            ));
        }
        if let Some(ref tool) = self.pdf_fallback_tool {
            if tool.trim().is_empty()
                || tool.contains('\0')
                || tool.contains(';')
                || tool.contains('&')
                || tool.contains('|')
            {
                return Err(PolyguardError::ConfigError(
                    "pdf_fallback_tool must be a valid executable name or path".into(),
                ));
            }
        }
        Ok(())
    }
}

// ============================================================================
// ByteMap Structural Model
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FileFormat {
    Jpeg,
    Png,
    Zip,
    Pdf,
    Html,
    Script,
    Executable,
    Archive,
    Unknown,
}

impl fmt::Display for FileFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jpeg => write!(f, "JPEG"),
            Self::Png => write!(f, "PNG"),
            Self::Zip => write!(f, "ZIP"),
            Self::Pdf => write!(f, "PDF"),
            Self::Html => write!(f, "HTML/JS"),
            Self::Script => write!(f, "SCRIPT"),
            Self::Executable => write!(f, "EXECUTABLE"),
            Self::Archive => write!(f, "ARCHIVE"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Compact `#[repr(u8)]` region tag for cache-friendly scanning.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionType {
    PreHeader = 0,
    Header = 1,
    Structure = 2,
    Metadata = 3,
    Comment = 4,
    EntropyData = 5,
    Gap = 6,
    TrailingData = 7,
}

impl RegionType {
    /// High-entropy pixel/compressed payloads (`EntropyData`) are skipped to avoid false positives.
    #[inline(always)]
    pub const fn is_scannable(self) -> bool {
        !matches!(self, Self::EntropyData)
    }
}

impl fmt::Display for RegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreHeader => write!(f, "PRE_HEADER"),
            Self::Header => write!(f, "HEADER"),
            Self::Structure => write!(f, "STRUCTURE"),
            Self::Metadata => write!(f, "METADATA"),
            Self::Comment => write!(f, "COMMENT"),
            Self::EntropyData => write!(f, "ENTROPY"),
            Self::Gap => write!(f, "GAP"),
            Self::TrailingData => write!(f, "TRAILING"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRegion {
    pub start: usize,
    pub end: usize,
    pub region_type: RegionType,
    pub label: Cow<'static, str>,
}

impl ByteRegion {
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteMap {
    pub file_size: usize,
    pub format: FileFormat,
    pub regions: Vec<ByteRegion>,
}

impl ByteMap {
    pub fn new(file_size: usize, format: FileFormat) -> Self {
        Self {
            file_size,
            format,
            regions: Vec::with_capacity(32),
        }
    }

    #[inline]
    pub fn push(
        &mut self,
        start: usize,
        end: usize,
        region_type: RegionType,
        label: impl Into<Cow<'static, str>>,
    ) {
        let clamped_start = start.min(self.file_size);
        let clamped_end = end.min(self.file_size);
        if clamped_end > clamped_start {
            self.regions.push(ByteRegion {
                start: clamped_start,
                end: clamped_end,
                region_type,
                label: label.into(),
            });
        }
    }

    /// Sort recorded regions and materialize unreferenced intervals as PreHeader/Gap/TrailingData.
    pub fn finalize(&mut self) {
        if self.file_size == 0 {
            return;
        }
        if self.regions.is_empty() {
            self.regions.push(ByteRegion {
                start: 0,
                end: self.file_size,
                region_type: RegionType::Gap,
                label: Cow::Borrowed("Unmapped file contents"),
            });
            return;
        }

        self.regions
            .sort_unstable_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

        let mut gaps = Vec::new();
        let mut cursor = 0usize;

        for (idx, region) in self.regions.iter().enumerate() {
            if region.start > cursor {
                let (rtype, label) = if idx == 0 && cursor == 0 {
                    (RegionType::PreHeader, Cow::Borrowed("Pre-header bytes"))
                } else {
                    (RegionType::Gap, Cow::Borrowed("Unreferenced inter-object gap"))
                };
                gaps.push(ByteRegion {
                    start: cursor,
                    end: region.start,
                    region_type: rtype,
                    label,
                });
            }
            if region.end > cursor {
                cursor = region.end;
            }
        }

        if cursor < self.file_size {
            gaps.push(ByteRegion {
                start: cursor,
                end: self.file_size,
                region_type: RegionType::TrailingData,
                label: Cow::Borrowed("Trailing bytes after EOF"),
            });
        }

        if !gaps.is_empty() {
            self.regions.extend(gaps);
            self.regions
                .sort_unstable_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
        }
    }

    #[inline]
    pub fn scannable_regions(&self) -> impl Iterator<Item = &ByteRegion> {
        self.regions.iter().filter(|r| r.region_type.is_scannable())
    }

    pub fn bytes_of_type(&self, rtype: RegionType) -> usize {
        self.regions
            .iter()
            .filter(|r| r.region_type == rtype)
            .map(ByteRegion::len)
            .sum()
    }
}

// ============================================================================
// Analysis, Parser Metadata & Report Models
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    Allow,
    Flag,
    Sanitize,
    Reject,
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Flag => write!(f, "FLAG"),
            Self::Sanitize => write!(f, "SANITIZE"),
            Self::Reject => write!(f, "REJECT"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    EmbeddedSignature,
    PreHeaderData,
    TrailingData,
    UnreferencedGap,
    OversizedMetadata,
    DangerousKeyword,
    InvalidChecksum,
    StructuralMismatch,
    ResourceLimitRisk,
    PathTraversal,
    LsbSteganography,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub offset: usize,
    pub length: usize,
    pub region_label: String,
    pub description: String,
    pub score: u32,
    pub whitelisted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_secondary_format: Option<FileFormat>,
}

#[derive(Debug, Clone, Default)]
pub struct ParserMetadataFlags {
    pub is_ooxml: bool,
    pub has_icc_profile: bool,
    pub has_pdf_incremental_updates: bool,
    pub has_pdf_embedded_files: bool,
    pub zip_entry_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParseResult {
    pub byte_map: ByteMap,
    pub parser_anomalies: Vec<Anomaly>,
    pub metadata_flags: ParserMetadataFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationSummary {
    pub performed: bool,
    pub dry_run: bool,
    pub isolated: bool,
    pub original_size: usize,
    pub sanitized_size: usize,
    pub removed_bytes: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub file_size: usize,
    pub detected_format: FileFormat,
    pub secondary_formats: Vec<FileFormat>,
    pub risk_score: u32,
    pub risk_level: Severity,
    pub action: PolicyAction,
    pub is_polyglot: bool,
    pub anomalies: Vec<Anomaly>,
    pub byte_map: ByteMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitization: Option<SanitizationSummary>,
}

impl AnalysisReport {
    pub fn is_suspicious(&self) -> bool {
        self.is_polyglot || !matches!(self.action, PolicyAction::Allow)
    }

    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}