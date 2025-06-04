use std::{
    collections::HashMap,
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use base64::Engine as _;
use ignore::WalkBuilder;
use mime_guess::MimeGuess;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Serialize, Deserialize, Clone)]
struct ScanConfig {
    /// Sample size in bytes (0 to disable sampling)
    sample_bytes: usize,
    /// Maximum file size to process (in bytes)
    max_file_size: u64,
    /// Skip files larger than this size for hashing
    skip_hash_size: u64,
    /// System paths to exclude (platform-specific defaults will be added)
    exclude_paths: Vec<String>,
    /// File extensions to prioritise for data discovery
    data_extensions: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct UploadConfig {
    /// Upload endpoint URL
    url: Option<String>,
    /// HTTP method (POST, PUT)
    method: String,
    /// Headers to include in upload
    headers: HashMap<String, String>,
    /// Upload batch size (number of records per request)
    batch_size: usize,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppConfig {
    scan: ScanConfig,
    upload: UploadConfig,
}

#[derive(Serialize)]
struct FileRecord<'a> {
    path: &'a str,
    size_bytes: u64,
    mode_octal: u32,
    mtime_rfc3339: String,
    sha256_hex: Option<String>,
    mime: String,
    sample_b64: Option<String>,
    is_data_file: bool,
    scan_timestamp: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            sample_bytes: 4096,
            max_file_size: 100 * 1024 * 1024, // 100MB
            skip_hash_size: 1024 * 1024 * 1024, // 1GB
            exclude_paths: get_default_exclude_paths(),
            data_extensions: vec![
                "txt".to_string(), "csv".to_string(), "json".to_string(),
                "xml".to_string(), "xlsx".to_string(), "docx".to_string(),
                "pdf".to_string(), "sql".to_string(), "log".to_string(),
                "dat".to_string(), "db".to_string(), "sqlite".to_string(),
                "tsv".to_string(), "yaml".to_string(), "yml".to_string(),
            ],
        }
    }
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            url: None,
            method: "POST".to_string(),
            headers: HashMap::new(),
            batch_size: 100,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            upload: UploadConfig::default(),
        }
    }
}

fn get_default_exclude_paths() -> Vec<String> {
    let mut paths = vec![
        // macOS system paths
        "/System".to_string(),
        "/Library".to_string(),
        "/Applications".to_string(),
        "/usr".to_string(),
        "/opt".to_string(),
        "/private".to_string(),
        "/tmp".to_string(),
        "/var".to_string(),
        
        // Windows system paths
        "C:\\Windows".to_string(),
        "C:\\Program Files".to_string(),
        "C:\\Program Files (x86)".to_string(),
        "C:\\ProgramData".to_string(),
        "C:\\Users\\Public".to_string(),
        
        // Common cache/temp directories
        ".cache".to_string(),
        ".git".to_string(),
        ".svn".to_string(),
        "node_modules".to_string(),
        "target".to_string(),
        "__pycache__".to_string(),
        ".DS_Store".to_string(),
        "Thumbs.db".to_string(),
        "desktop.ini".to_string(),
        
        // SECURITY-SENSITIVE DIRECTORIES - CRITICAL EXCLUSIONS
        // SSH keys and certificates (NEVER scan these!)
        ".ssh".to_string(),
        "ssh".to_string(),
        ".gnupg".to_string(),
        ".pgp".to_string(),
        
        // Browser data containing cookies, passwords, tokens
        "Google/Chrome".to_string(),
        "Mozilla/Firefox".to_string(),
        "Microsoft/Edge".to_string(),
        "Safari".to_string(),
        "Brave".to_string(),
        "Opera".to_string(),
        "Application Support/Google".to_string(),
        "Application Support/Mozilla".to_string(),
        "Application Support/Safari".to_string(),
        "Application Support/Brave".to_string(),
        
        // Password managers and credential stores
        "1Password".to_string(),
        "LastPass".to_string(),
        "Bitwarden".to_string(),
        "KeePass".to_string(),
        "Keychain".to_string(),
        "Keychains".to_string(),
        "Application Support/1Password".to_string(),
        "Application Support/LastPass".to_string(),
        "Application Support/Bitwarden".to_string(),
        
        // Windows credential directories
        "Microsoft/Credentials".to_string(),
        "Microsoft/Crypto".to_string(),
        "Microsoft/SystemCertificates".to_string(),
        "Microsoft/Protect".to_string(),
        "Roaming/Microsoft/Credentials".to_string(),
        "Local/Microsoft/Credentials".to_string(),
        
        // Email and communication apps
        "Microsoft/Outlook".to_string(),
        "Mail".to_string(),
        "Thunderbird".to_string(),
        "Slack".to_string(),
        "Discord".to_string(),
        "Teams".to_string(),
        "WhatsApp".to_string(),
        "Telegram".to_string(),
        
        // Development tools with sensitive data
        ".aws".to_string(),
        ".azure".to_string(),
        ".gcloud".to_string(),
        ".kube".to_string(),
        ".docker".to_string(),
        ".helm".to_string(),
        ".terraform".to_string(),
        
        // VPN and security software
        ".vpn".to_string(),
        "VPN".to_string(),
        "Cisco".to_string(),
        "OpenVPN".to_string(),
        "NordVPN".to_string(),
        "ExpressVPN".to_string(),
        
        // IDE and editor sensitive configs
        ".vscode".to_string(),
        ".idea".to_string(),
        ".android".to_string(),
        ".gradle".to_string(),
    ];
    
    // Add user-specific system and sensitive paths
    if let Ok(home) = std::env::var("HOME") {
        paths.extend(vec![
            // macOS user system directories
            format!("{}/Library", home),
            format!("{}/.Trash", home),
            format!("{}/.npm", home),
            format!("{}/.cargo", home),
            format!("{}/.rustup", home),
            
            // CRITICAL: User-specific sensitive directories
            format!("{}/.ssh", home),
            format!("{}/.gnupg", home),
            format!("{}/.pgp", home),
            format!("{}/.aws", home),
            format!("{}/.azure", home),
            format!("{}/.gcloud", home),
            format!("{}/.kube", home),
            format!("{}/.docker", home),
            
            // macOS browser and app data
            format!("{}/Library/Application Support/Google", home),
            format!("{}/Library/Application Support/Mozilla", home),
            format!("{}/Library/Application Support/Safari", home),
            format!("{}/Library/Application Support/Brave", home),
            format!("{}/Library/Application Support/1Password", home),
            format!("{}/Library/Application Support/LastPass", home),
            format!("{}/Library/Application Support/Bitwarden", home),
            format!("{}/Library/Keychains", home),
            format!("{}/Library/Mail", home),
            format!("{}/Library/Messages", home),
            format!("{}/Library/Calendars", home),
            format!("{}/Library/Cookies", home),
            
            // Additional macOS sensitive paths
            format!("{}/Library/Application Support/Slack", home),
            format!("{}/Library/Application Support/Discord", home),
            format!("{}/Library/Application Support/Microsoft", home),
            format!("{}/Library/Application Support/Cisco", home),
        ]);
    }
    
    // Add Windows user-specific paths
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        paths.extend(vec![
            format!("{}/.ssh", userprofile),
            format!("{}\\.ssh", userprofile),
            format!("{}\\AppData\\Roaming\\Microsoft\\Credentials", userprofile),
            format!("{}\\AppData\\Local\\Microsoft\\Credentials", userprofile),
            format!("{}\\AppData\\Roaming\\Microsoft\\Crypto", userprofile),
            format!("{}\\AppData\\Local\\Google\\Chrome", userprofile),
            format!("{}\\AppData\\Roaming\\Mozilla\\Firefox", userprofile),
            format!("{}\\AppData\\Local\\Microsoft\\Edge", userprofile),
            format!("{}\\AppData\\Local\\1Password", userprofile),
            format!("{}\\AppData\\Roaming\\1Password", userprofile),
        ]);
    }
    
    paths
}

fn load_config(config_path: &Path) -> anyhow::Result<AppConfig> {
    if !config_path.exists() {
        // Create default config file
        let default_config = AppConfig::default();
        let config_str = toml::to_string_pretty(&default_config)?;
        
        fs::write(config_path, config_str)?;
        
        println!("Created default configuration file: {}", config_path.display());
        return Ok(default_config);
    }
    
    let config_str = fs::read_to_string(config_path)?;
    let config: AppConfig = toml::from_str(&config_str)?;
    
    Ok(config)
}

fn should_include_path(path: &Path, exclude_paths: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    
    // Check against configured exclude paths
    for exclude_pattern in exclude_paths {
        if path_str.contains(exclude_pattern) {
            return false;
        }
    }
    
    // CRITICAL SECURITY: Block sensitive file extensions and names
    if let Some(filename) = path.file_name() {
        let filename_str = filename.to_string_lossy().to_lowercase();
        
        // Block SSH keys and certificates
        let sensitive_extensions = [
            ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks", ".keystore",
            ".rsa", ".dsa", ".ecdsa", ".ed25519", ".pub", ".ppk",
        ];
        
        let sensitive_filenames = [
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys",
            ".netrc", ".pgpass", "keyring", "keychain", "wallet.dat",
            "cookies.txt", "cookies.sqlite", "cookies.db", "logins.json", "key3.db", "key4.db",
            "signons.sqlite", "formhistory.sqlite", "cert8.db", "cert9.db", "secmod.db",
            "credentials", "accessTokens.json", "credentials.db",
            "master.passwd", "signons.txt", "passwd", "shadow", "gshadow", "sudoers",
        ];
        
        // Check for sensitive extensions
        for ext in &sensitive_extensions {
            if filename_str.ends_with(ext) {
                eprintln!("SECURITY: Skipping sensitive file: {}", path.display());
                return false;
            }
        }
        
        // Check for sensitive filenames
        for name in &sensitive_filenames {
            if filename_str.contains(name) {
                eprintln!("SECURITY: Skipping sensitive file: {}", path.display());
                return false;
            }
        }
        
        // Block any file in .ssh directory (extra safety)
        if path_str.contains("/.ssh/") || path_str.contains("\\.ssh\\") {
            eprintln!("SECURITY: Skipping file in SSH directory: {}", path.display());
            return false;
        }
        
        // Block SSH config specifically (but allow other config files)
        if filename_str == "config" && (path_str.contains("/.ssh/") || path_str.contains("\\.ssh\\")) {
            eprintln!("SECURITY: Skipping SSH config file: {}", path.display());
            return false;
        }
        
        // Block credential files in cloud provider directories
        if (filename_str.contains("credentials") || filename_str.contains("config")) && 
           (path_str.contains("/.aws/") || path_str.contains("/.azure/") || 
            path_str.contains("/.gcloud/") || path_str.contains("\\.aws\\") || 
            path_str.contains("\\.azure\\") || path_str.contains("\\.gcloud\\")) {
            eprintln!("SECURITY: Skipping cloud credentials: {}", path.display());
            return false;
        }
        
        // Block browser profile directories
        if path_str.contains("Profile") && (
            path_str.contains("Chrome") || 
            path_str.contains("Firefox") || 
            path_str.contains("Safari") || 
            path_str.contains("Edge")
        ) {
            return false;
        }
    }
    
    // Skip if path contains system indicators
    let components: Vec<String> = path.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    
    for component in &components {
        if component.starts_with('.') && 
           (component.contains("cache") || component.contains("tmp") || component.contains("temp")) {
            return false;
        }
        
        // Additional security check for component names
        let comp_lower = component.to_lowercase();
        if comp_lower.contains("password") || 
           comp_lower.contains("credential") || 
           comp_lower.contains("keychain") ||
           comp_lower.contains("token") ||
           comp_lower.contains("secret") {
            return false;
        }
    }
    
    true
}

fn is_data_file(path: &Path, mime: &str, data_extensions: &[String]) -> bool {
    // Check by extension
    if let Some(ext) = path.extension() {
        if let Some(ext_str) = ext.to_str() {
            if data_extensions.iter()
                .any(|e| e.eq_ignore_ascii_case(ext_str)) {
                return true;
            }
        }
    }
    
    // Check by MIME type
    mime.starts_with("text/") || 
    mime.contains("json") || 
    mime.contains("xml") || 
    mime.contains("csv") ||
    mime.contains("spreadsheet") ||
    mime.contains("database")
}

fn process_file(path: &Path, writer: &Mutex<BufWriter<File>>, config: &ScanConfig) -> anyhow::Result<()> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    
    // Skip files that are too large
    if size > config.max_file_size {
        return Ok(());
    }
    
    // Get file mode (permissions) - Unix only, default to 0 on Windows
    #[cfg(unix)]
    let mode = meta.mode();
    #[cfg(not(unix))]
    let mode = 0u32;
    
    let mtime = OffsetDateTime::from(meta.modified()?)
        .format(&Rfc3339)?;
    
    // Read sample and calculate hash
    let mut file = File::open(path)?;
    let sample_size = config.sample_bytes.min(size as usize);
    let mut sample_buf = vec![0; sample_size];
    
    if sample_size > 0 {
        file.read_exact(&mut sample_buf)?;
    }
    
    let sample_b64 = if sample_size > 0 {
        Some(base64::engine::general_purpose::STANDARD.encode(&sample_buf))
    } else {
        None
    };
    
    // Calculate hash if file isn't too large
    let hash_hex = if size <= config.skip_hash_size {
        let mut hasher = Sha256::new();
        hasher.update(&sample_buf);
        
        if size > sample_size as u64 {
            // Read rest of file for hash
            let mut remaining = Vec::new();
            file.read_to_end(&mut remaining)?;
            hasher.update(&remaining);
        }
        
        Some(hex::encode(hasher.finalize()))
    } else {
        None
    };
    
    let mime = MimeGuess::from_path(path)
        .first_or_octet_stream()
        .to_string();
    
    let is_data_file_flag = is_data_file(path, &mime, &config.data_extensions);
    
    let record = FileRecord {
        path: path.to_str().unwrap_or("<invalid>"),
        size_bytes: size,
        mode_octal: mode & 0o7777,
        mtime_rfc3339: mtime,
        sha256_hex: hash_hex,
        mime,
        sample_b64,
        is_data_file: is_data_file_flag,
        scan_timestamp: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
    };
    
    // Serialise one line of NDJSON
    let json = serde_json::to_string(&record)?;
    let mut guard = writer.lock().unwrap();
    guard.write_all(json.as_bytes())?;
    guard.write_all(b"\n")?;
    
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mut root_path = PathBuf::from(".");
    let mut config_path = PathBuf::from("scanner-config.toml");
    let mut output_path = PathBuf::from("scan.ndjson");
    
    // Simple argument parsing
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--path" | "-p" => {
                if i + 1 < args.len() {
                    root_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: --path requires a value");
                    std::process::exit(1);
                }
            }
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: --config requires a value");
                    std::process::exit(1);
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: --output requires a value");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                println!("Data Discovery Tool");
                println!("Usage: {} [OPTIONS]", args[0]);
                println!("Options:");
                println!("  -p, --path <PATH>      Root path to scan (default: current directory)");
                println!("  -c, --config <FILE>    Configuration file (default: scanner-config.toml)");
                println!("  -o, --output <FILE>    Output file (default: scan.ndjson)");
                println!("  -h, --help             Show this help message");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }
    
    // Load configuration
    let config = load_config(&config_path)?;
    
    println!("Data Discovery Tool");
    println!("Scanning: {}", root_path.display());
    println!("Output: {}", output_path.display());
    println!("Max file size: {} MB", config.scan.max_file_size / (1024 * 1024));
    
    if let Some(url) = &config.upload.url {
        println!("Upload URL configured: {}", url);
    }
    
    // Set up writer
    let file = File::create(&output_path)?;
    let writer = Mutex::new(BufWriter::new(file));
    
    // Build ignore-aware walker with enhanced filtering
    let exclude_paths = config.scan.exclude_paths.clone();
    let walker = WalkBuilder::new(&root_path)
        .hidden(false)
        .ignore(true)
        .parents(true)
        .max_depth(Some(20))
        .filter_entry(move |entry| should_include_path(entry.path(), &exclude_paths))
        .build_parallel();
    
    let mut file_count = 0u64;
    let start_time = std::time::Instant::now();
    
    walker.run(|| {
        let config = config.clone();
        let writer_ref = &writer;
        Box::new(move |result| {
            if let Ok(entry) = result {
                let path = entry.path();
                if path.is_file() {
                    if let Err(e) = process_file(path, writer_ref, &config.scan) {
                        eprintln!("Warning: Failed to process {}: {}", path.display(), e);
                    } else {
                        // Note: This isn't thread-safe counting, but gives rough progress
                        if file_count % 1000 == 0 {
                            println!("Processed ~{} files...", file_count);
                        }
                        file_count += 1;
                    }
                }
            }
            ignore::WalkState::Continue
        })
    });
    
    let elapsed = start_time.elapsed();
    println!("\nScan complete!");
    println!("Processed files in {:.2}s", elapsed.as_secs_f64());
    println!("Results written to: {}", output_path.display());
    
    Ok(())
}