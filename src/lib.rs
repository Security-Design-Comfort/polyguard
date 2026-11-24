//! # polyguard
//!
//! Compact, hardware-optimized Pure Rust library for strict binary parsing,
//! region-based polyglot detection, policy/whitelist evaluation, and isolated
//! Content Disarm & Reconstruction (CDR).

pub mod detect;
pub mod ingest;
pub mod parse;
pub mod sanitize;
pub mod types;

use crate::ingest::InputBuffer;
use crate::sanitize::IsolationContext;
use crate::types::{AnalysisReport, PolicyConfig, Result};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

/// Run Stages 1–4 on an in-memory byte slice.
pub fn analyze_bytes(
    data: &[u8],
    file_path: Option<String>,
    config: &PolicyConfig,
) -> Result<AnalysisReport> {
    ingest::validate_input_size(data, config)?;
    let parsed = parse::parse_auto(data, config)?;
    let anomalies = detect::detect_anomalies(data, &parsed, config);
    Ok(detect::evaluate_policy(
        file_path,
        data.len(),
        parsed,
        anomalies,
        config,
    ))
}

/// Run Stages 1–4 on a file on disk using hybrid zero-copy `mmap` / heap I/O.
pub fn analyze_file(path: &Path, config: &PolicyConfig) -> Result<AnalysisReport> {
    let buffer = InputBuffer::from_file(path, config)?;
    analyze_bytes(buffer.as_slice(), Some(path.display().to_string()), config)
}

/// Parallel batch analysis across all CPU cores using Rayon work-stealing.
pub fn analyze_files_parallel(
    paths: &[PathBuf],
    config: &PolicyConfig,
) -> Vec<(PathBuf, Result<AnalysisReport>)> {
    paths
        .par_iter()
        .map(|p| (p.clone(), analyze_file(p, config)))
        .collect()
}

/// Run the full 5-stage pipeline (Analysis + CDR Sanitization) on in-memory bytes.
pub fn sanitize_bytes_full(
    data: &[u8],
    file_path: Option<String>,
    config: &PolicyConfig,
    isolation: &IsolationContext,
    dry_run: bool,
) -> Result<(AnalysisReport, Option<Vec<u8>>)> {
    let mut report = analyze_bytes(data, file_path, config)?;
    let (clean, summary) =
        sanitize::sanitize_bytes(data, report.detected_format, config, isolation, dry_run)?;
    report.sanitization = Some(summary);
    Ok((report, clean))
}

/// Run the full 5-stage pipeline on disk and write clean output when `dry_run` is false.
pub fn sanitize_file(
    input: &Path,
    output: Option<&Path>,
    config: &PolicyConfig,
    isolation: &IsolationContext,
    dry_run: bool,
) -> Result<AnalysisReport> {
    let buffer = InputBuffer::from_file(input, config)?;
    let (report, clean_opt) = sanitize_bytes_full(
        buffer.as_slice(),
        Some(input.display().to_string()),
        config,
        isolation,
        dry_run,
    )?;

    if let Some(clean_bytes) = clean_opt {
        let target = output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_sanitized_path(input));
        fs::write(&target, clean_bytes)?;
    }
    Ok(report)
}

fn default_sanitized_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    match input.extension() {
        Some(ext) => input.with_file_name(format!("{}.clean.{}", stem, ext.to_string_lossy())),
        None => input.with_file_name(format!("{}.clean", stem)),
    }
}
