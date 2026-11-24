# Polyguard — Polyglot Detection, LSB Steganalysis & Isolated CDR Engine

`polyguard` is a high-performance Pure Rust security engine and CLI tool that strictly parses binary file structures (**JPEG, PNG, ZIP/ZIP64, PDF**), partitions every byte from `0x00` to `EOF` into a structural `ByteMap`, detects polyglot payloads and sequential Least Significant Bit (LSB) steganography with near-zero false positives, and neutralizes threats via OS-isolated Content Disarm & Reconstruction (CDR).

---

## Key Capabilities

| Category                     | Capabilities                                                                                                                                                                                                                                                                                                                          |
| :--------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Supported Formats**        | **JPEG** (ISO/IEC 10918-1), **PNG** (W3C / ISO 15948), **ZIP & ZIP64** (PKWARE APPNOTE with `deflate`, `bzip2`, `zstd`, `lzma`), **PDF** (ISO 32000)                                                                                                                                                                                  |
| **Polyglot Detection**       | Appenders (post-`EOI`/`IEND`/`EOCD`/`%%EOF`), Prependers (pre-`SOI`/`%PDF-`/`LFH`), unreferenced inter-object cavities (`Gap`), oversized metadata/comments, and active PDF keywords (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/RichMedia`, `/XFA`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE`, `/EmbeddedFile`) |
| **Steganalysis & Pixel CDR** | Westfeld-Pfitzmann Chi-Square ($\chi^2$) Pair-of-Values (PoV) LSB detection across $10\%$, $25\%$, $50\%$, and $100\%$ PNG pixel prefixes + RGB bit-0 normalization (`strip_lsb_on_sanitize`) preserving PNG alpha opacity                                                                                                            |
| **DoS & Safety Guardrails**  | File size caps, pixel-flood dimension/allocation limits, zip bomb entry/uncompressed/ratio budgets, zip slip path traversal blocking, and automatic `fstatfs` network/FUSE mount detection (prevents remote `mmap` `SIGBUS`)                                                                                                          |
| **Cross-Platform Isolation** | Dedicated `__cdr-worker` child process with wall-clock timeouts, Unix `setrlimit` (`RLIMIT_AS` with `RLIMIT_DATA` fallback, `RLIMIT_CPU`, `RLIMIT_CORE = 0`), and Windows Job Objects (`JOB_OBJECT_LIMIT_PROCESS_MEMORY \| JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`)                                                                       |
| **PDF Rebuilding**           | Pure Rust object disarmament, orphan pruning, and xref reconstruction via `lopdf`, with optional isolated external subprocess fallback (`pdf_fallback_tool`, e.g., `qpdf` or `mutool`)                                                                                                                                                |

---
## Installation

### Option 1: Download Prebuilt Binaries (Recommended for End Users)
Download the release archive for your operating system from the **Releases** page. Extract it then run with the command appropriate for your OS. No Rust toolchain or external runtime dependencies are required.

```bash
# Linux / macOS
chmod +x polyguard
./polyguard --help

# Windows (PowerShell)
.\polyguard.exe --help
```

### Option 2: Build from Source
Requires **Rust 1.85+** (recommended **1.88+**) for `edition = "2024"`, `lopdf = "0.47"`, and `image = "0.25.10"`.

```bash
git clone https://github.com/Security-Design-Comfort/Polyguard.git
cd Polyguard

# Standard portable release build (opt-level = 3, fat LTO, single codegen unit)
cargo build --release

# Optional: optimize specifically for the host CPU (AVX2 / NEON / PCLMULQDQ)
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The compiled executable is placed at `target/release/polyguard` on Linux or `target\release\polyguard.exe` on Windows.

---

## CLI Usage

```bash
# Show help

polyguard --help
# Deep structural inspection, anomalies, LSB steganalysis, and Byte Map
polyguard inspect suspect.png

# Output structural Byte Map only (aligned ASCII table or JSON)
polyguard map --json document.pdf

# Parallel multi-core recursive directory scan with a custom policy
polyguard scan --recursive --policy policy.toml ./uploads/

# Scan mutable network shares (NFS/SMB/FUSE) with mmap explicitly disabled
polyguard scan --no-mmap --recursive /mnt/shared_uploads/

# Sanitize a polyglot or LSB-embedded file (isolated worker enabled by default)
polyguard sanitize suspect.jpg -o clean.jpg

# Preview CDR actions without writing output, or run in-process without worker spawn
polyguard sanitize --dry-run suspect.pdf
polyguard sanitize --no-isolation suspect.zip -o clean.zip
```
Note: use `.\polyguard.exe` instead of `polyguard` if you are on Windows
### Global Flags

| Flag | Description |
| :--- | :--- |
| `--policy <PATH>` | Load custom security guardrails and whitelists from a TOML file |
| `--strict` | Override policy strictness to `strict` |
| `--no-mmap` | Disable memory-mapped I/O and force safe heap-buffered reads |
| `--json` | Emit machine-readable JSON output for SIEM or CI/CD pipelines |

### `sanitize` Subcommand Options

| Flag | Description |
| :--- | :--- |
| `-o, --output <PATH>` | Destination path for clean output (defaults to `<name>.clean.<ext>`) |
| `--dry-run` | Preview CDR actions and produce an audit report without writing a file |
| `--no-isolation` | Run CDR directly in-process instead of spawning `__cdr-worker` |

### Exit Codes (CI/CD & Git Hooks)

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Clean / Allowed / Sanitized cleanly |
| `1` | Polyglot, LSB steganography, or suspicious anomaly detected |
| `2` | Execution error, I/O failure, DoS guardrail violation, or malformed file |

---

## Policy Configuration (`policy.toml`)

Key configurable parameters in `policy.toml`:

| Setting | Default | Purpose |
| :--- | :--- | :--- |
| `strictness` | `"balanced"` | Decision mode: `"strict"`, `"balanced"`, or `"permissive"` |
| `max_file_size_bytes` | `104857600` | Maximum input file size ($100\text{ MiB}$) |
| `allow_mmap` | `true` | Enables local zero-copy `mmap` (auto-disabled on network/FUSE mounts) |
| `mmap_threshold_bytes` | `65536` | Threshold ($64\text{ KiB}$) above which zero-copy `mmap` is used |
| `max_image_pixels` | `100000000` | Pixel-flood protection ceiling ($100\text{ MP}$) |
| `max_zip_compression_ratio` | `100.0` | Zip Bomb decompression ratio limit ($100:1$) |
| `enable_lsb_detection` | `true` | Runs Chi-Square ($\chi^2$) PoV steganalysis on decoded PNG RGB channels |
| `lsb_chi_square_threshold` | `0.99` | PoV probability threshold in $(0.0, 1.0]$ |
| `jpeg_reencode_quality` | `92` | Output JPEG quality ($1\text{..=}100$) during destructive re-encoding |
| `strip_lsb_on_sanitize` | `true` | Clears bit $0$ of RGB channels during JPEG/PNG CDR |
| `pdf_fallback_tool` | *(unset)* | Optional isolated external rebuilder (e.g., `"qpdf"` or `"mutool"`) |
| `enable_process_isolation` | `true` | Runs Stage 5 CDR inside a resource-capped `__cdr-worker` subprocess |
| `worker_timeout_ms` | `15000` | Wall-clock execution deadline per file ($15\text{ s}$) |
| `worker_memory_limit_bytes` | `536870912` | $512\text{ MiB}$ cap enforced via Unix `setrlimit` / Windows Job Object |

---

## Repository Structure & Documentation

```text
polyguard/
├── Cargo.toml        # Crate manifest and dependencies
├── policy.toml       # Default security policy and whitelists
├── README.md         # Documentation
└── src/
    ├── lib.rs        # Core analysis & sanitization entry points
    ├── main.rs       # CLI subcommands & __cdr-worker entrypoint
    ├── types.rs      # PolicyConfig, ByteMap, and AnalysisReport types
    ├── ingest.rs     # Hybrid mmap/heap I/O and DoS guardrails
    ├── parse.rs      # Strict binary parsers (JPEG, PNG, ZIP/ZIP64, PDF)
    ├── detect.rs     # SIMD Aho-Corasick scanner, heuristics, and LSB χ²
    └── sanitize.rs   # OS-isolated __cdr-worker and format rebuilders
```