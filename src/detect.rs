//! Stage 3 (Region-Based Anomaly Detection) & Stage 4 (Whitelist & Policy Engine).
//!
//! Runs a single-pass SIMD Aho-Corasick DFA and structural heuristics exclusively
//! across non-entropy regions (`ByteMap::scannable_regions`), eliminating pixel-region
//! false positives, then applies whitelist rules and risk scoring.

use crate::ingest::validate_image_dimensions;
use crate::types::{
    AnalysisReport, Anomaly, AnomalyKind, ByteRegion, FileFormat, ParseResult, ParserMetadataFlags,
    PolicyAction, PolicyConfig, RegionType, Severity, Strictness,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use image::codecs::png::PngDecoder;
use image::{DynamicImage, ImageDecoder, Limits};
use memchr::memmem;
use std::io::Cursor;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
pub struct SignatureRule {
    pub id: &'static str,
    pub pattern: &'static [u8],
    pub format: FileFormat,
    pub severity: Severity,
    pub score: u32,
}

pub const SIGNATURES: &[SignatureRule] = &[
    SignatureRule {
        id: "ZIP Local File Header",
        pattern: b"PK\x03\x04",
        format: FileFormat::Zip,
        severity: Severity::Critical,
        score: 85,
    },
    SignatureRule {
        id: "ZIP End of Central Directory",
        pattern: b"PK\x05\x06",
        format: FileFormat::Zip,
        severity: Severity::High,
        score: 70,
    },
    SignatureRule {
        id: "PDF Document Header",
        pattern: b"%PDF-",
        format: FileFormat::Pdf,
        severity: Severity::Critical,
        score: 85,
    },
    SignatureRule {
        id: "PNG Image Signature",
        pattern: b"\x89PNG\r\n\x1a\n",
        format: FileFormat::Png,
        severity: Severity::High,
        score: 75,
    },
    SignatureRule {
        id: "JPEG SOI+Marker",
        pattern: b"\xFF\xD8\xFF",
        format: FileFormat::Jpeg,
        severity: Severity::High,
        score: 70,
    },
    SignatureRule {
        id: "ELF Executable Header",
        pattern: b"\x7fELF",
        format: FileFormat::Executable,
        severity: Severity::Critical,
        score: 95,
    },
    SignatureRule {
        id: "PE/DOS Executable Stub",
        pattern: b"MZ\x90\x00",
        format: FileFormat::Executable,
        severity: Severity::Critical,
        score: 95,
    },
    SignatureRule {
        id: "HTML Script Tag",
        pattern: b"<script",
        format: FileFormat::Html,
        severity: Severity::Critical,
        score: 85,
    },
    SignatureRule {
        id: "HTML Script Tag (Upper)",
        pattern: b"<SCRIPT",
        format: FileFormat::Html,
        severity: Severity::Critical,
        score: 85,
    },
    SignatureRule {
        id: "HTML Document",
        pattern: b"<!DOCTYPE html",
        format: FileFormat::Html,
        severity: Severity::High,
        score: 70,
    },
    SignatureRule {
        id: "HTML Root Element",
        pattern: b"<html>",
        format: FileFormat::Html,
        severity: Severity::High,
        score: 70,
    },
    SignatureRule {
        id: "PHP Script Tag",
        pattern: b"<?php",
        format: FileFormat::Script,
        severity: Severity::Critical,
        score: 90,
    },
    SignatureRule {
        id: "POSIX Shell Shebang",
        pattern: b"#!/bin/sh",
        format: FileFormat::Script,
        severity: Severity::Critical,
        score: 90,
    },
    SignatureRule {
        id: "Bash Shell Shebang",
        pattern: b"#!/bin/bash",
        format: FileFormat::Script,
        severity: Severity::Critical,
        score: 90,
    },
    SignatureRule {
        id: "Env Script Shebang",
        pattern: b"#!/usr/bin/env",
        format: FileFormat::Script,
        severity: Severity::Critical,
        score: 90,
    },
    SignatureRule {
        id: "RAR Archive Signature",
        pattern: b"Rar!\x1a\x07",
        format: FileFormat::Archive,
        severity: Severity::High,
        score: 75,
    },
    SignatureRule {
        id: "7-Zip Archive Signature",
        pattern: b"7z\xBC\xAF\x27\x1C",
        format: FileFormat::Archive,
        severity: Severity::High,
        score: 75,
    },
];

static AUTOMATON: OnceLock<AhoCorasick> = OnceLock::new();

#[inline]
fn automaton() -> &'static AhoCorasick {
    AUTOMATON.get_or_init(|| {
        let patterns: Vec<&[u8]> = SIGNATURES.iter().map(|s| s.pattern).collect();
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("static signature table must compile")
    })
}

/// Evaluate structural heuristics on a single non-entropy region.
fn evaluate_region_heuristics(
    region: &ByteRegion,
    data: &[u8],
    primary_format: FileFormat,
    config: &PolicyConfig,
    out: &mut Vec<Anomaly>,
) {
    let len = region.len();
    if len == 0 {
        return;
    }

    match region.region_type {
        RegionType::PreHeader => out.push(Anomaly {
            kind: AnomalyKind::PreHeaderData,
            severity: Severity::High,
            offset: region.start,
            length: len,
            region_label: region.label.to_string(),
            description: format!(
                "{} bytes prepended before primary {} header",
                len, primary_format
            ),
            score: 65,
            whitelisted: false,
            detected_secondary_format: None,
        }),
        RegionType::TrailingData => {
            let slice = &data[region.start..region.end];
            let benign_pad = len <= 4 && slice.iter().all(|&b| b == 0 || b.is_ascii_whitespace());
            let (severity, score) = if benign_pad {
                (Severity::Info, 5)
            } else {
                (Severity::High, 60)
            };
            out.push(Anomaly {
                kind: AnomalyKind::TrailingData,
                severity,
                offset: region.start,
                length: len,
                region_label: region.label.to_string(),
                description: format!(
                    "{} trailing bytes detected after {} EOF terminator",
                    len, primary_format
                ),
                score,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }
        RegionType::Gap => {
            let (severity, score) = if len >= 32 {
                (Severity::High, 50)
            } else {
                (Severity::Medium, 25)
            };
            out.push(Anomaly {
                kind: AnomalyKind::UnreferencedGap,
                severity,
                offset: region.start,
                length: len,
                region_label: region.label.to_string(),
                description: format!(
                    "unreferenced cavity of {} bytes between structural segments",
                    len
                ),
                score,
                whitelisted: false,
                detected_secondary_format: None,
            });
        }
        RegionType::Metadata if len > config.max_metadata_region_bytes => out.push(Anomaly {
            kind: AnomalyKind::OversizedMetadata,
            severity: Severity::Medium,
            offset: region.start,
            length: len,
            region_label: region.label.to_string(),
            description: format!(
                "metadata region '{}' is {} bytes (threshold: {} bytes)",
                region.label, len, config.max_metadata_region_bytes
            ),
            score: 30,
            whitelisted: false,
            detected_secondary_format: None,
        }),
        RegionType::Comment if len > 4096 => out.push(Anomaly {
            kind: AnomalyKind::OversizedMetadata,
            severity: Severity::Medium,
            offset: region.start,
            length: len,
            region_label: region.label.to_string(),
            description: format!(
                "oversized comment segment '{}' ({} bytes)",
                region.label, len
            ),
            score: 30,
            whitelisted: false,
            detected_secondary_format: None,
        }),
        _ => {}
    }
}

/// Stage 3: Scan all non-entropy regions for structural heuristics and embedded signatures.
pub fn detect_anomalies(
    data: &[u8],
    parse_result: &ParseResult,
    config: &PolicyConfig,
) -> Vec<Anomaly> {
    let mut findings = parse_result.parser_anomalies.clone();
    let primary = parse_result.byte_map.format;
    let ac = automaton();

    for region in parse_result.byte_map.scannable_regions() {
        evaluate_region_heuristics(region, data, primary, config, &mut findings);

        let slice = &data[region.start..region.end];
        for m in ac.find_iter(slice) {
            let rule = &SIGNATURES[m.pattern().as_usize()];

            // Ignore primary format's own framing signatures inside its Header/Structure regions.
            if primary == rule.format
                && matches!(
                    region.region_type,
                    RegionType::Header | RegionType::Structure
                )
            {
                continue;
            }
            // Allow standard EXIF embedded JPEG thumbnails inside APP1 (EXIF).
            if primary == FileFormat::Jpeg
                && rule.format == FileFormat::Jpeg
                && region.label == "APP1 (EXIF)"
            {
                continue;
            }

            findings.push(Anomaly {
                kind: AnomalyKind::EmbeddedSignature,
                severity: rule.severity,
                offset: region.start + m.start(),
                length: m.end() - m.start(),
                region_label: region.label.to_string(),
                description: format!(
                    "embedded {} signature ('{}') found inside {} region '{}'",
                    rule.format, rule.id, region.region_type, region.label
                ),
                score: rule.score,
                whitelisted: false,
                detected_secondary_format: Some(rule.format),
            });
        }
    }

    // 3. Optional pixel-domain LSB steganalysis (Chi-Square Pair-of-Values test on PNG).
    if config.enable_lsb_detection && primary == FileFormat::Png {
        if let Some(lsb_anomaly) = detect_lsb_steganography(data, config) {
            findings.push(lsb_anomaly);
        }
    }

    findings
}

/// Decodes a PNG image under strict `PolicyConfig` dimension and memory guardrails and
/// runs a Westfeld-Pfitzmann Chi-Square Pair-of-Values (PoV) test over increasing pixel
/// prefixes (10%, 25%, 50%, 100%) across R, G, and B channels to detect sequential LSB embedding.
pub fn detect_lsb_steganography(data: &[u8], config: &PolicyConfig) -> Option<Anomaly> {
    let sig_offset = memmem::find(data, b"\x89PNG\r\n\x1a\n")?;
    let slice = &data[sig_offset..];

    let mut decoder = PngDecoder::new(Cursor::new(slice)).ok()?;
    let (w, h) = decoder.dimensions();
    validate_image_dimensions(w, h, config).ok()?;

    let mut limits = Limits::default();
    limits.max_image_width = Some(config.max_image_width);
    limits.max_image_height = Some(config.max_image_height);
    limits.max_alloc = Some(config.max_decode_memory_bytes);
    decoder.set_limits(limits).ok()?;

    let rgb = DynamicImage::from_decoder(decoder).ok()?.to_rgb8();
    let raw = rgb.as_raw();
    let pixel_count = raw.len() / 3;
    if pixel_count < 256 {
        return None;
    }

    let channels = [("Red", 0usize), ("Green", 1usize), ("Blue", 2usize)];
    let fractions = [0.10_f64, 0.25, 0.50, 1.00];

    for frac in fractions {
        let sample_pixels = ((pixel_count as f64) * frac) as usize;
        if sample_pixels < 256 {
            continue;
        }

        for &(channel_name, offset) in &channels {
            let mut hist = [0u64; 256];
            for px in 0..sample_pixels {
                hist[raw[px * 3 + offset] as usize] += 1;
            }

            if let Some((chi2, prob)) = chi_square_pov_probability(&hist) {
                if prob >= config.lsb_chi_square_threshold {
                    return Some(Anomaly {
                        kind: AnomalyKind::LsbSteganography,
                        severity: Severity::High,
                        offset: sig_offset,
                        length: slice.len(),
                        region_label: format!("PNG Pixel Plane ({})", channel_name),
                        description: format!(
                            "LSB steganography suspected in {} channel ({:.0}% prefix, chi2={:.2}, PoV p={:.4})",
                            channel_name,
                            frac * 100.0,
                            chi2,
                            prob
                        ),
                        score: 55,
                        whitelisted: false,
                        detected_secondary_format: None,
                    });
                }
            }
        }
    }

    None
}

/// Computes the Westfeld-Pfitzmann Chi-Square PoV statistic across `(2k, 2k+1)` value pairs
/// and approximates the upper-tail probability `P(X >= chi2)` via the Wilson-Hilferty transform.
fn chi_square_pov_probability(hist: &[u64; 256]) -> Option<(f64, f64)> {
    let mut chi2 = 0.0_f64;
    let mut active_pairs = 0usize;

    for k in 0..128 {
        let even = hist[2 * k] as f64;
        let odd = hist[2 * k + 1] as f64;
        // Require at least 4 observations per pair to suppress sparse-bin distortion.
        if even + odd >= 4.0 {
            let expected = (even + odd) * 0.5;
            let diff = even - expected;
            chi2 += (diff * diff) / expected;
            active_pairs += 1;
        }
    }

    if active_pairs < 16 {
        return None;
    }

    let dof = (active_pairs - 1) as f64;
    let term = 2.0 / (9.0 * dof);
    let z = ((chi2 / dof).cbrt() - (1.0 - term)) / term.sqrt();
    let prob = 0.5 * erfc(z / std::f64::consts::SQRT_2);
    Some((chi2, prob))
}

/// Abramowitz & Stegun (7.1.26) approximation for the complementary error function `erfc(x)`.
fn erfc(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.3275911 * x.abs());
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let approx = poly * (-x * x).exp();
    if x >= 0.0 {
        approx
    } else {
        2.0 - approx
    }
}

/// Apply Stage 4 whitelist suppressions for legitimate multi-stream/metadata structures.
fn apply_whitelist(
    anomalies: &mut [Anomaly],
    primary_format: FileFormat,
    flags: &ParserMetadataFlags,
    config: &PolicyConfig,
) {
    let wl = &config.whitelist;
    let icc_has_payload = anomalies.iter().any(|a| {
        a.kind == AnomalyKind::EmbeddedSignature
            && (a.region_label.contains("ICC_PROFILE") || a.region_label == "iCCP")
    });

    for a in anomalies.iter_mut() {
        if matches!(
            a.kind,
            AnomalyKind::PathTraversal | AnomalyKind::ResourceLimitRisk
        ) {
            continue;
        }
        if wl.allow_standard_icc_profile
            && flags.has_icc_profile
            && !icc_has_payload
            && a.kind == AnomalyKind::OversizedMetadata
            && (a.region_label.contains("ICC_PROFILE") || a.region_label == "iCCP")
        {
            a.whitelisted = true;
            continue;
        }
        if wl.allow_ooxml
            && primary_format == FileFormat::Zip
            && flags.is_ooxml
            && a.kind == AnomalyKind::OversizedMetadata
        {
            a.whitelisted = true;
            continue;
        }
        if primary_format == FileFormat::Png
            && a.kind == AnomalyKind::OversizedMetadata
            && wl
                .allowed_png_ancillary_chunks
                .iter()
                .any(|c| a.region_label.contains(c))
        {
            a.whitelisted = true;
            continue;
        }
        if primary_format == FileFormat::Pdf {
            if wl.allow_pdf_incremental_updates
                && a.kind == AnomalyKind::StructuralMismatch
                && a.region_label == "PDF Revisions"
            {
                a.whitelisted = true;
            } else if wl.allow_pdf_embedded_files
                && a.kind == AnomalyKind::DangerousKeyword
                && a.description.contains("/EmbeddedFile")
            {
                a.whitelisted = true;
            }
        }
    }
}

/// Stage 4: Score non-whitelisted findings, classify polyglot status, and emit `AnalysisReport`.
pub fn evaluate_policy(
    file_path: Option<String>,
    file_size: usize,
    parse_result: ParseResult,
    mut anomalies: Vec<Anomaly>,
    config: &PolicyConfig,
) -> AnalysisReport {
    let primary_format = parse_result.byte_map.format;
    apply_whitelist(
        &mut anomalies,
        primary_format,
        &parse_result.metadata_flags,
        config,
    );

    let mut secondary_formats = Vec::new();
    let mut risk_score = 0u32;
    let mut max_severity = Severity::Info;
    let (mut has_embedded_sig, mut has_prepender_or_appender) = (false, false);

    for a in &anomalies {
        if a.whitelisted {
            continue;
        }
        risk_score = risk_score.saturating_add(a.score);
        if a.severity > max_severity {
            max_severity = a.severity;
        }
        if let Some(sec) = a.detected_secondary_format {
            has_embedded_sig = true;
            if sec != primary_format && !secondary_formats.contains(&sec) {
                secondary_formats.push(sec);
            }
        }
        if matches!(
            a.kind,
            AnomalyKind::PreHeaderData | AnomalyKind::TrailingData
        ) && a.severity >= Severity::High
        {
            has_prepender_or_appender = true;
        }
    }

    let is_polyglot =
        has_embedded_sig || !secondary_formats.is_empty() || has_prepender_or_appender;

    let risk_level = if risk_score >= 80 || max_severity == Severity::Critical {
        Severity::Critical
    } else if risk_score >= 50 || max_severity == Severity::High {
        Severity::High
    } else if risk_score >= 25 || max_severity == Severity::Medium {
        Severity::Medium
    } else if risk_score > 0 {
        Severity::Low
    } else {
        Severity::Info
    };

    let action = match config.strictness {
        Strictness::Strict => {
            if risk_score == 0 {
                PolicyAction::Allow
            } else if risk_level >= Severity::Critical {
                PolicyAction::Reject
            } else {
                PolicyAction::Sanitize
            }
        }
        Strictness::Balanced => {
            if risk_score == 0 {
                PolicyAction::Allow
            } else if risk_level == Severity::Low {
                PolicyAction::Flag
            } else if risk_level >= Severity::Critical
                && anomalies
                    .iter()
                    .any(|a| !a.whitelisted && a.kind == AnomalyKind::PathTraversal)
            {
                PolicyAction::Reject
            } else {
                PolicyAction::Sanitize
            }
        }
        Strictness::Permissive => {
            if risk_level <= Severity::Medium {
                if risk_score == 0 {
                    PolicyAction::Allow
                } else {
                    PolicyAction::Flag
                }
            } else {
                PolicyAction::Sanitize
            }
        }
    };

    AnalysisReport {
        file_path,
        file_size,
        detected_format: primary_format,
        secondary_formats,
        risk_score,
        risk_level,
        action,
        is_polyglot,
        anomalies,
        byte_map: parse_result.byte_map,
        sanitization: None,
    }
}
