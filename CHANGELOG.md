# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-06-04

### Added

#### Core Features
- **Smart Data Discovery**: Identifies data files based on extensions and MIME types
- **Comprehensive Metadata Extraction**: Captures file size, permissions, modification time, SHA256 hash
- **Content Sampling**: Extracts configurable samples (4KB default) for content analysis
- **Structured Output**: Generates NDJSON format for easy processing and integration

#### Security-First Design
- **Comprehensive Security Exclusions**: Prevents scanning sensitive files that could trigger security software
- **SSH Key Protection**: Blocks all SSH private keys, certificates, and related files
- **Browser Data Protection**: Excludes browser cookies, saved passwords, and profile data
- **Password Manager Protection**: Blocks 1Password, LastPass, Bitwarden, and system keychains
- **Cloud Credential Protection**: Excludes AWS, Azure, Google Cloud, Docker, and Kubernetes credentials
- **VPN Configuration Protection**: Blocks VPN configs and security software directories
- **Enterprise Security Compatibility**: Tested with CrowdStrike Falcon and other security tools

#### Performance & Scalability
- **Configurable File Size Limits**: 100MB default maximum file size for processing
- **Intelligent Hash Calculation**: Skips SHA256 for files larger than 1GB (configurable)
- **Parallel Processing**: Uses ignore-aware parallel walking for efficient filesystem traversal
- **Memory Efficient**: Streams large files and manages memory usage carefully
- **Configurable Throttling**: Optional delay between operations to minimize system impact

#### Cross-Platform Support
- **macOS System Path Filtering**: Excludes `/System`, `/Library`, `/Applications`, user directories
- **Windows System Path Filtering**: Excludes `C:\Windows`, `C:\Program Files`, credential stores
- **Universal Development Filtering**: Skips `.git`, `node_modules`, `target`, cache directories
- **Platform-Specific Security**: Handles different credential storage locations per OS

#### Configuration & Usability
- **Auto-Generated Configuration**: Creates `scanner-config.toml` with secure defaults on first run
- **Command-Line Interface**: Supports `--path`, `--config`, `--output`, `--help` options
- **Security Warnings**: Clear documentation about security exclusions and their importance
- **Flexible Exclusion Patterns**: Easy to add custom paths and patterns to exclude

#### Upload & Integration Ready
- **HTTP Endpoint Support**: Compatible with REST APIs and webhooks
- **AWS S3 Integration**: Supports presigned URLs for direct S3 uploads
- **Authentication Headers**: Configurable headers for API authentication
- **Batch Upload Support**: Configurable batch sizes for efficient data transfer
- **Multiple Output Formats**: NDJSON with extensible record structure

#### Data Classification Features
- **File Type Detection**: Advanced MIME type detection and classification
- **Data File Prioritization**: Configurable list of data file extensions (CSV, JSON, XML, etc.)
- **Content-Based Classification**: `is_data_file` flag for automatic data file identification
- **Metadata Timestamps**: Scan timestamps for audit trails and versioning

### Security Considerations
- **Zero Sensitive File Exposure**: Tool designed to never access SSH keys, passwords, or credentials
- **Enterprise Environment Ready**: Security exclusions prevent triggering of security software
- **Audit Trail**: All scanned files logged with timestamps for compliance
- **Configurable Security**: Exclusion patterns can be extended for custom security requirements

### Technical Implementation
- **Language**: Rust for memory safety and performance
- **Dependencies**: Minimal, security-focused dependency tree
- **Error Handling**: Comprehensive error handling with informative messages
- **Cross-Platform**: Single codebase supports Windows, macOS, and Linux
- **CI/CD Ready**: GitHub Actions workflows for testing and multi-platform builds

[0.1.0]: https://github.com/ciaran-finnegan/file-scanner/releases/tag/v0.1.0 