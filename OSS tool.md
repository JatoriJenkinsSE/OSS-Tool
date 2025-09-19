# OSS Tool
# sentry-lite (Rust) — Open-Source Security Tool

> **Owner:** `JatoriJenkinsSE`
> **Repo name:** `OSS Tool.md`

A fast, portable Rust security CLI with three practical scanners you can run locally or in CI:

* **Secrets scan** — regex-based detection for common creds (AWS, Google, generic API tokens, private keys)
* **Port scan** — async TCP connect scans (host/port ranges)
* **Permissions scan** — flag world-writable files and directories

No external network calls (except your explicit port scans). Designed for quick wins, small codebase, and strong defaults.

---

## Repository Layout

```
.
├─ Cargo.toml
├─ README.md
├─ LICENSE
├─ SECURITY.md
├─ .gitignore
├─ .github/
│  └─ workflows/ci.yml
├─ Dockerfile
└─ src/
   ├─ main.rs
   ├─ secrets.rs
   ├─ ports.rs
   └─ perms.rs
```

---

## `Cargo.toml`

```toml
[package]
name = "sentry-lite"
version = "0.1.0"
edition = "2021"
authors = ["JatoriJenkinsSE"]
description = "Small, fast security CLI: secrets, ports, permissions"
license = "MIT OR Apache-2.0"
repository = "https://github.com/JatoriJenkinsSE/sentry-lite"

[dependencies]
anyhow = "1"
thiserror = "1"
clap = { version = "4", features = ["derive"] }
regex = "1"
walkdir = "2"
ignore = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
console = "0.15"
indicatif = "0.17"
tokio = { version = "1", features = ["full"] }
futures = "0.3"
```

---

## `src/main.rs`

```rust
use clap::{Parser, Subcommand};
use anyhow::Result;

mod secrets;
mod ports;
mod perms;

#[derive(Parser)]
#[command(name = "sentry-lite", about = "Security CLI: secrets, ports, perms")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan repository/files for hard-coded secrets
    Secrets {
        /// Path to start scanning (dir or file)
        #[arg(default_value = ".")]
        path: String,
        /// Output JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Scan TCP ports on a host (connect scan)
    Ports {
        /// Host (IP or DNS)
        host: String,
        /// Ports (e.g. 1-1024 or 22,80,443)
        ports: String,
        /// Max concurrent connections
        #[arg(long, default_value_t = 200)]
        concurrency: usize,
        /// Timeout in ms per connection
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        /// Output JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Flag world-writable files/dirs under a path
    Perms {
        /// Path to scan
        #[arg(default_value = ".")]
        path: String,
        /// Output JSON instead of text
        #[arg(long)]
        json: bool,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Secrets { path, json } => secrets::run(&path, json)?,
        Commands::Ports { host, ports, concurrency, timeout_ms, json } => {
            ports::run(&host, &ports, concurrency, timeout_ms, json).await?;
        }
        Commands::Perms { path, json } => perms::run(&path, json)?,
    }
    Ok(())
}
```

---

## `src/secrets.rs`

```rust
use anyhow::Result;
use ignore::WalkBuilder;
use regex::Regex;
use serde::Serialize;
use std::path::Path;
use console::style;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub pattern: String,
    pub excerpt: String,
}

pub fn run(path: &str, json: bool) -> Result<()> {
    let patterns = vec![
        // AWS Access Key ID + Secret patterns (heuristic)
        ("AWS_KEY", Regex::new(r"AKIA[0-9A-Z]{16}")?),
        ("AWS_SECRET", Regex::new(r"(?i)aws(.{0,20})?(secret|access)?.{0,5}[:=].{0,5}([A-Za-z0-9/+=]{40})")?),
        // Private keys
        ("PRIVATE_KEY", Regex::new(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")?),
        // Generic tokens
        ("BEARER_TOKEN", Regex::new(r"(?i)(api|secret|token|bearer).{0,5}[:=].{0,5}[A-Za-z0-9_\-]{20,}")?),
        // Google API key
        ("GCP_API_KEY", Regex::new(r"AIza[0-9A-Za-z\-_]{35}")?),
    ];

    let mut findings: Vec<Finding> = Vec::new();

    let walker = WalkBuilder::new(path)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build();

    for dent in walker {
        let dent = match dent { Ok(d) => d, Err(_) => continue };
        if dent.file_type().map(|t| t.is_dir()).unwrap_or(false) { continue; }
        let p = dent.path();
        if should_skip(p) { continue; }
        let content = match std::fs::read_to_string(p) { Ok(c) => c, Err(_) => continue };
        for (name, rx) in &patterns {
            for (i, line) in content.lines().enumerate() {
                if let Some(m) = rx.find(line) {
                    let excerpt = &line[m.start()..m.end()].chars().take(80).collect::<String>();
                    findings.push(Finding {
                        path: p.display().to_string(),
                        line: i + 1,
                        pattern: name.to_string(),
                        excerpt: excerpt.to_string(),
                    });
                }
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        if findings.is_empty() {
            println!("{} No findings.", style("✔").green());
        } else {
            println!("{} Findings: {}", style("!" ).yellow(), findings.len());
            for f in findings {
                println!("{} {}:{} [{}] {}", style("→").cyan(), f.path, f.line, f.pattern, f.excerpt);
            }
        }
    }

    Ok(())
}

fn should_skip(p: &Path) -> bool {
    let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // Avoid scanning binaries, images, etc.
    let skip_ext = [
        "png","jpg","jpeg","gif","pdf","zip","tar","gz","xz","7z","iso","exe","dll","so","wasm","class","jar","bin"
    ];
    if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
        if skip_ext.contains(&ext) { return true; }
    }
    // Skip large files > 2MB for speed
    if let Ok(md) = std::fs::metadata(p) {
        if md.len() > 2 * 1024 * 1024 { return true; }
    }
    // Skip lockfiles generated by package managers except Cargo.lock (useful for parsing later)
    if fname.ends_with("package-lock.json") || fname.ends_with("pnpm-lock.yaml") { return true; }
    false
}
```

---

## `src/ports.rs`

```rust
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::Serialize;
use std::net::ToSocketAddrs;
use tokio::{net::TcpStream, time::{timeout, Duration}};
use console::style;

#[derive(Debug, Serialize)]
pub struct OpenPort { pub port: u16 }

pub async fn run(host: &str, ports: &str, concurrency: usize, timeout_ms: u64, json: bool) -> Result<()> {
    let targets = expand_ports(ports)?;
    let dur = Duration::from_millis(timeout_ms);

    let mut futs = FuturesUnordered::new();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut open: Vec<OpenPort> = Vec::new();

    for port in targets {
        let host = host.to_string();
        let sem = sem.clone();
        let permit = sem.acquire_owned().await?;
        futs.push(tokio::spawn(async move {
            let _permit = permit; // keep until end of task
            let addr = format!("{}:{}", host, port);
            // Resolve synchronously to avoid async DNS dependency
            let resolved = (addr.as_str()).to_socket_addrs().ok()?.next()?;
            match timeout(dur, TcpStream::connect(resolved)).await {
                Ok(Ok(_)) => Some(OpenPort { port }),
                _ => None,
            }
        }));
    }

    while let Some(res) = futs.next().await { if let Ok(Some(p)) = res { open.push(p) } }

    open.sort_by_key(|p| p.port);

    if json {
        println!("{}", serde_json::to_string_pretty(&open)?);
    } else {
        if open.is_empty() { println!("{} No open ports.", style("✔").green()); }
        else {
            println!("{} Open ports:", style("✔").green());
            for p in open { println!("  {}", p.port); }
        }
    }

    Ok(())
}

fn expand_ports(spec: &str) -> Result<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let s = part.trim();
        if s.is_empty() { continue; }
        if let Some((a,b)) = s.split_once('-') {
            let start: u16 = a.parse()?;
            let end: u16 = b.parse()?;
            for p in start.min(end)..=start.max(end) { out.push(p); }
        } else {
            out.push(s.parse()?);
        }
    }
    out.sort(); out.dedup();
    Ok(out)
}
```

---

## `src/perms.rs`

```rust
use anyhow::Result;
use serde::Serialize;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
use walkdir::WalkDir;
use console::style;

#[derive(Debug, Serialize)]
pub struct PermFinding { pub path: String, pub mode_octal: String }

pub fn run(path: &str, json: bool) -> Result<()> {
    let mut findings: Vec<PermFinding> = Vec::new();

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if let Ok(md) = fs::metadata(p) {
            #[cfg(unix)]
            {
                let mode = md.permissions().mode();
                // world-writable bit (others write) is 0o002
                if mode & 0o002 != 0 {
                    findings.push(PermFinding { path: p.display().to_string(), mode_octal: format!("{:o}", mode) });
                }
            }
        }
    }

    if json { println!("{}", serde_json::to_string_pretty(&findings)?); }
    else {
        if findings.is_empty() { println!("{} No world-writable files/dirs.", style("✔").green()); }
        else {
            println!("{} World-writable items:", style("!" ).yellow());
            for f in findings { println!("  {} ({})", f.path, f.mode_octal); }
        }
    }

    Ok(())
}
```

---

## `README.md`

````md
# sentry-lite

**Small, fast security CLI** by **@JatoriJenkinsSE**. Run three kinds of scans locally or in CI.

### Features
- Secrets detection (regex-based)
- Async TCP port scanner
- World-writable permissions check

### Install (Rust)
```bash
cargo install --path .
````

### Usage

```bash
# Secrets
sentry-lite secrets ./ --json

# Ports
sentry-lite ports 127.0.0.1 1-1024 --concurrency 300 --timeout-ms 300

# Permissions
sentry-lite perms ./
```

### CI Example (GitHub Actions)

See `.github/workflows/ci.yml` — fails the job if findings are detected (optional step you can add).

### Caveats

* Regex heuristics can produce false positives; review findings before acting.
* Port scans should only be run on hosts you own or are authorized to test.

````

---

## `.github/workflows/ci.yml`
```yaml
name: CI
on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
      - name: Build
        run: cargo build --locked --all-targets
      - name: Test
        run: cargo test --locked
      - name: Lint (clippy)
        run: cargo clippy -- -D warnings
````

---

## `Dockerfile`

```dockerfile
FROM rust:1.80 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /app/target/release/sentry-lite /usr/local/bin/sentry-lite
ENTRYPOINT ["/usr/local/bin/sentry-lite"]
```

---

## `SECURITY.md`

```md
# Security Policy

If you believe you’ve found a security issue in **sentry-lite**, please do not open a public issue. Email **security@users.noreply.github.com** with details. You’ll receive an acknowledgement within 72 hours.

## Supported Versions
We support the latest minor version from `main`.

## Reporting Guidelines
- Provide reproduction steps and affected versions.
- Attach logs or minimal test repos when possible.
```

---

## `LICENSE`

```text
MIT OR Apache-2.0 — choose either license when using this software.
```

---

## `.gitignore`

```gitignore
target/
**/*.log
**/*.tmp
.DS_Store
```

---

## Quickstart (tailored for @JatoriJenkinsSE)

```bash
# Initialize the repo
git init

git add .
git commit -m "feat: initial release of sentry-lite (secrets/ports/perms)"

git branch -M main
git remote add origin https://github.com/JatoriJenkinsSE/sentry-lite.git

git push -u origin main
```

---

## Optional: Fail CI on findings

Add a final CI step per scanner, e.g. secrets:

```yaml
      - name: Secrets scan
        run: |
          OUT=$(cargo run --quiet --bin sentry-lite -- secrets . --json || true)
          echo "$OUT"
          COUNT=$(echo "$OUT" | jq '. | length')
          if [ "$COUNT" != "0" ]; then
            echo "Secret(s) found: $COUNT" >&2
            exit 1
          fi
```

---

## Notes / Future Work

* Add allowlist regexes and path globs via `--allowlist`.
* Add SARIF output for GitHub code scanning.
* Add `--max-file-size` CLI option and binary file detection via magic bytes.
* Optional dependency audit subcommand using offline advisory DB.
* Windows ACL checks for permissions (current perms check is Unix-focused).
