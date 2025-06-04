# Data Discovery Tool

A high-performance file discovery and classification tool designed for identifying and cataloguing data across file systems whilst minimising system impact.

## Features

### 🎯 **Smart Data Discovery**
- Identifies data files based on extensions and MIME types
- Extracts metadata: size, permissions, modification time, SHA256 hash
- Captures file samples for content analysis
- Generates structured NDJSON output for easy processing

### 🚫 **Intelligent System Filtering**
- Pre-configured exclusion patterns for macOS and Windows system files
- Skips common development artifacts and cache directories
- Configurable exclude paths for custom environments
- Respects `.gitignore` and similar ignore files

### ⚡ **Performance Optimised**
- Configurable rate limiting to minimise system impact
- File size limits to avoid processing massive files
- Optional hash calculation for large files
- Parallel processing with configurable concurrency
- Progress reporting with real-time statistics

### 📤 **Flexible Upload Options**
- Supports HTTP endpoints (REST APIs, webhooks)
- Configurable authentication headers
- Batch uploads for efficiency
- Streaming upload option for real-time processing
- S3 presigned URL support

## Installation

```bash
git clone <repository-url>
cd data-discovery-tool
cargo build --release
```

## Quick Start

```bash
# Scan current directory with default settings
./target/release/file_scanner

# Scan specific path
./target/release/file_scanner --path /Users/username/Documents

# Use custom configuration
./target/release/file_scanner --config my-config.toml --output results.ndjson

# Dry run (no uploads)
./target/release/file_scanner --dry-run
```

## Configuration

The tool uses a TOML configuration file (`scanner-config.toml` by default). On first run, a default configuration file is created.

### Scan Configuration

```toml
[scan]
# Sample size for content analysis (bytes)
sample_bytes = 4096

# Maximum file size to process (100MB default)
max_file_size = 104857600

# Delay between operations (milliseconds) - reduces system impact
throttle_ms = 10

# Maximum concurrent operations
max_parallel = 4

# Skip hashing for files larger than this (1GB default)
skip_hash_size = 1073741824

# Additional paths to exclude
exclude_paths = [
    "/custom/path/to/exclude",
    "C:\\Custom\\Windows\\Path"
]

# File extensions prioritised for data discovery
data_extensions = [
    "txt", "csv", "json", "xml", "xlsx", "docx", "pdf",
    "sql", "log", "dat", "db", "sqlite"
]
```

### Upload Configuration

```toml
[upload]
# Upload endpoint (leave empty to disable)
url = "https://your-api.com/data-discovery/upload"

# HTTP method
method = "POST"

# Custom headers for authentication
[upload.headers]
Authorization = "Bearer your-token-here"
X-API-Key = "your-api-key"

# Records per upload batch
batch_size = 100

# Upload while scanning (vs at end)
streaming = false
```

## System Path Filtering

The tool automatically excludes common system paths:

### macOS
- `/System`, `/Library`, `/Applications`
- `/usr`, `/opt`, `/private`, `/tmp`, `/var`
- `~/Library`, `~/.Trash`, development caches

### Windows
- `C:\Windows`, `C:\Program Files`, `C:\ProgramData`
- `C:\Users\Public`

### Cross-platform
- `.git`, `.svn`, `node_modules`, `target`, `__pycache__`
- `.DS_Store`, `Thumbs.db`, `desktop.ini`

## Output Format

Each line in the output NDJSON file contains:

```json
{
  "path": "/path/to/file.txt",
  "size_bytes": 1024,
  "mode_octal": 420,
  "mtime_rfc3339": "2023-12-01T10:00:00Z",
  "sha256_hex": "abc123...",
  "mime": "text/plain",
  "sample_b64": "base64-encoded-sample",
  "is_data_file": true,
  "scan_timestamp": "2023-12-01T10:00:00Z"
}
```

## Upload Destinations

### AWS S3 (Presigned URL)
```toml
[upload]
url = "https://bucket.s3.region.amazonaws.com/path?X-Amz-Signature=..."
method = "PUT"
```

### REST API
```toml
[upload]
url = "https://api.example.com/data-discovery"
method = "POST"

[upload.headers]
Authorization = "Bearer your-jwt-token"
Content-Type = "application/x-ndjson"
```

### Webhook (Slack, Discord, etc.)
```toml
[upload]
url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
method = "POST"
```

## Performance Tuning

### For Low-Impact Scanning
```toml
[scan]
throttle_ms = 50        # Slower processing
max_parallel = 2        # Fewer concurrent operations
max_file_size = 10485760 # 10MB limit
skip_hash_size = 100485760 # Skip hashing for 100MB+ files
```

### For Fast Scanning
```toml
[scan]
throttle_ms = 0         # No delays
max_parallel = 8        # More concurrency
max_file_size = 1073741824 # 1GB limit
sample_bytes = 1024     # Smaller samples
```

## Use Cases

### Data Classification Pipeline
1. Run discovery tool to identify data files
2. Upload results to classification service
3. Process samples for sensitive data detection
4. Generate compliance reports

### Security Auditing
1. Scan systems for unexpected data files
2. Identify files in system directories
3. Check for configuration or credential files
4. Generate security inventory

### Data Migration
1. Inventory existing data before migration
2. Classify files by type and importance
3. Estimate migration time and resources
4. Validate migration completeness

## Development

```bash
# Run with debug output
RUST_LOG=debug cargo run -- --path test-data

# Run tests
cargo test

# Format code
cargo fmt

# Check for issues
cargo clippy
```

## License

This project is licensed under the MIT License. 