//! Polyguard CLI frontend with CI/CD exit codes (`0` clean, `1` detected, `2` error)
//! and hidden `__cdr-worker` mode for Stage 5 process isolation.

use clap::{Parser, Subcommand};
use polyguard::sanitize::{apply_worker_resource_limits, sanitize_in_process, IsolationContext};
use polyguard::types::{AnalysisReport, ByteMap, FileFormat, PolicyConfig, Strictness};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use walkdir::WalkDir;

const EXIT_CLEAN: u8 = 0;
const EXIT_DETECTED: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Debug, Parser)]
#[command(name = "polyguard", version, about = "Polyglot Detection & CDR Engine")]
struct Cli {
    /// Custom TOML policy file (defaults to built-in enterprise guardrails)
    #[arg(long, global = true)]
    policy: Option<PathBuf>,

    /// Enforce strict policy mode
    #[arg(long, global = true)]
    strict: bool,

    /// Disable memory-mapped I/O and force safe heap-buffered reads (recommended on volatile shares)
    #[arg(long, global = true)]
    no_mmap: bool,

    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Deep structural inspection, anomaly detection, and Byte Map visualization
    Inspect { path: PathBuf },

    /// Output the structural Byte Map from offset 0x00 to EOF
    Map { path: PathBuf },

    /// Scan a file or directory (parallelized across CPU cores)
    Scan {
        path: PathBuf,
        #[arg(short, long)]
        recursive: bool,
    },

    /// Neutralize polyglot payloads via Content Disarm & Reconstruction (CDR)
    Sanitize {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        no_isolation: bool,
    },

    /// Internal isolated worker subprocess
    #[command(name = "__cdr-worker", hide = true)]
    CdrWorker {
        #[arg(long)]
        format: String,
        #[arg(long)]
        policy_json: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Commands::CdrWorker {
        format,
        policy_json,
    } = cli.command
    {
        return run_worker(&format, &policy_json);
    }

    let mut config = match &cli.policy {
        Some(p) => match PolicyConfig::from_toml_file(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading policy: {}", e);
                return ExitCode::from(EXIT_ERROR);
            }
        },
        None => PolicyConfig::default(),
    };
    if cli.strict {
        config.strictness = Strictness::Strict;
    }
    if cli.no_mmap {
        config.allow_mmap = false;
    }

    match cli.command {
        Commands::Inspect { path } => match polyguard::analyze_file(&path, &config) {
            Ok(report) => {
                let suspicious = report.is_suspicious();
                print_report(&report, cli.json, true);
                ExitCode::from(if suspicious { EXIT_DETECTED } else { EXIT_CLEAN })
            }
            Err(e) => {
                eprintln!("Error inspecting {}: {}", path.display(), e);
                ExitCode::from(EXIT_ERROR)
            }
        },
        Commands::Map { path } => match polyguard::analyze_file(&path, &config) {
            Ok(report) => {
                if cli.json {
                    match serde_json::to_string_pretty(&report.byte_map) {
                        Ok(s) => println!("{}", s),
                        Err(e) => {
                            eprintln!("JSON error: {}", e);
                            return ExitCode::from(EXIT_ERROR);
                        }
                    }
                } else {
                    print_byte_map(&report.byte_map);
                }
                ExitCode::from(EXIT_CLEAN)
            }
            Err(e) => {
                eprintln!("Error mapping {}: {}", path.display(), e);
                ExitCode::from(EXIT_ERROR)
            }
        },
        Commands::Scan { path, recursive } => {
            if path.is_file() {
                match polyguard::analyze_file(&path, &config) {
                    Ok(report) => {
                        let suspicious = report.is_suspicious();
                        print_report(&report, cli.json, false);
                        ExitCode::from(if suspicious { EXIT_DETECTED } else { EXIT_CLEAN })
                    }
                    Err(e) => {
                        eprintln!("Error scanning {}: {}", path.display(), e);
                        ExitCode::from(EXIT_ERROR)
                    }
                }
            } else if path.is_dir() {
                let walker = if recursive {
                    WalkDir::new(&path)
                } else {
                    WalkDir::new(&path).max_depth(1)
                };
                let files: Vec<PathBuf> = walker
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.into_path())
                    .collect();

                let results = polyguard::analyze_files_parallel(&files, &config);
                let (mut any_detected, mut any_error) = (false, false);
                let mut json_reports = Vec::new();

                for (p, res) in results {
                    match res {
                        Ok(report) => {
                            if report.is_suspicious() {
                                any_detected = true;
                            }
                            if cli.json {
                                json_reports.push(report);
                            } else {
                                print_report(&report, false, false);
                            }
                        }
                        Err(e) => {
                            any_error = true;
                            eprintln!("Error scanning {}: {}", p.display(), e);
                        }
                    }
                }

                if cli.json {
                    if let Ok(s) = serde_json::to_string_pretty(&json_reports) {
                        println!("{}", s);
                    }
                }
                if any_detected {
                    ExitCode::from(EXIT_DETECTED)
                } else if any_error {
                    ExitCode::from(EXIT_ERROR)
                } else {
                    ExitCode::from(EXIT_CLEAN)
                }
            } else {
                eprintln!("Target path does not exist: {}", path.display());
                ExitCode::from(EXIT_ERROR)
            }
        }
        Commands::Sanitize {
            path,
            output,
            dry_run,
            no_isolation,
        } => {
            if no_isolation {
                config.enable_process_isolation = false;
            }
            let isolation = IsolationContext::from_current_exe(&config);
            match polyguard::sanitize_file(&path, output.as_deref(), &config, &isolation, dry_run) {
                Ok(report) => {
                    print_report(&report, cli.json, false);
                    ExitCode::from(EXIT_CLEAN)
                }
                Err(e) => {
                    eprintln!("Sanitization failed for {}: {}", path.display(), e);
                    ExitCode::from(EXIT_ERROR)
                }
            }
        }
        Commands::CdrWorker { .. } => unreachable!(),
    }
}

fn run_worker(format_str: &str, policy_json: &str) -> ExitCode {
    let config: PolicyConfig = match serde_json::from_str(policy_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invalid worker policy JSON: {}", e);
            return ExitCode::from(EXIT_ERROR);
        }
    };
    if let Err(e) = apply_worker_resource_limits(&config) {
        eprintln!("worker rlimit error: {}", e);
        return ExitCode::from(EXIT_ERROR);
    }
    let format = match format_str {
        "jpeg" => FileFormat::Jpeg,
        "png" => FileFormat::Png,
        "zip" => FileFormat::Zip,
        "pdf" => FileFormat::Pdf,
        other => {
            eprintln!("unsupported worker format: {}", other);
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let mut input = Vec::new();
    if let Err(e) = io::stdin()
        .take(config.max_file_size_bytes.saturating_add(1))
        .read_to_end(&mut input)
    {
        eprintln!("worker stdin error: {}", e);
        return ExitCode::from(EXIT_ERROR);
    }

    match sanitize_in_process(&input, format, &config) {
        Ok((clean, notes)) => {
            for n in notes {
                eprintln!("{}", n);
            }
            if let Err(e) = io::stdout().write_all(&clean) {
                eprintln!("worker stdout error: {}", e);
                return ExitCode::from(EXIT_ERROR);
            }
            ExitCode::from(EXIT_CLEAN)
        }
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn print_byte_map(byte_map: &ByteMap) {
    println!(
        "Byte Map [Format: {} | Total Size: {} bytes]",
        byte_map.format, byte_map.file_size
    );
    println!(
        "{:<12} {:<12} {:<10} {:<12} {:<10} LABEL",
        "START", "END", "LENGTH", "TYPE", "SCAN?"
    );
    println!("{}", "-".repeat(78));
    for r in &byte_map.regions {
        println!(
            "{:#010x}   {:#010x}   {:<10} {:<12} {:<10} {}",
            r.start,
            r.end,
            r.len(),
            r.region_type,
            if r.region_type.is_scannable() { "yes" } else { "skip" },
            r.label
        );
    }
}

fn print_report(report: &AnalysisReport, as_json: bool, include_map: bool) {
    if as_json {
        match report.to_json_pretty() {
            Ok(s) => println!("{}", s),
            Err(e) => eprintln!("JSON error: {}", e),
        }
        return;
    }

    println!("==============================================================================");
    if let Some(ref p) = report.file_path {
        println!("File            : {}", p);
    }
    println!(
        "Format          : {} ({} bytes)",
        report.detected_format, report.file_size
    );
    if !report.secondary_formats.is_empty() {
        let secs: Vec<String> = report.secondary_formats.iter().map(ToString::to_string).collect();
        println!("Hidden Formats  : {}", secs.join(", "));
    }
    println!(
        "Verdict         : {} | Polyglot: {} | Risk: {} (score {})",
        report.action,
        if report.is_polyglot { "YES" } else { "NO" },
        report.risk_level,
        report.risk_score
    );

    if report.anomalies.is_empty() {
        println!("Anomalies       : None (Clean)");
    } else {
        println!("Anomalies ({})  :", report.anomalies.len());
        for (i, a) in report.anomalies.iter().enumerate() {
            let wl = if a.whitelisted { " [WHITELISTED]" } else { "" };
            println!(
                "  {:>2}. [{:<8}] @{:#010x} ({} B) {:?} - {}{}",
                i + 1,
                a.severity,
                a.offset,
                a.length,
                a.kind,
                a.description,
                wl
            );
        }
    }

    if let Some(ref cdr) = report.sanitization {
        println!(
            "CDR Sanitize    : performed={} dry_run={} isolated={} ({} B -> {} B, removed {} B)",
            cdr.performed,
            cdr.dry_run,
            cdr.isolated,
            cdr.original_size,
            cdr.sanitized_size,
            cdr.removed_bytes
        );
        for note in &cdr.notes {
            println!("  - {}", note);
        }
    }

    if include_map {
        println!();
        print_byte_map(&report.byte_map);
    }
    println!("==============================================================================");
}