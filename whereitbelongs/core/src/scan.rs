use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionKind {
	Signature { name: String, family: String },
	Heuristic { description: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
	pub path: PathBuf,
	pub kind: DetectionKind,
	pub severity: u8,
	pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
	pub include_extensions: Option<Vec<String>>, // lowercase without dot, e.g., ["exe","dll","js"]
	pub enable_heuristics: bool,
	pub max_file_size_bytes: u64,
}

impl Default for ScanOptions {
	fn default() -> Self {
		Self {
			include_extensions: None,
			enable_heuristics: true,
			max_file_size_bytes: 16 * 1024 * 1024, // 16 MiB
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
struct SignatureEntry {
	name: String,
	family: String,
	pattern: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SignatureDbRaw {
	signatures: Vec<SignatureEntry>,
}

struct SignatureDb {
	patterns: Vec<(String, String, Regex)>,
}

impl SignatureDb {
	fn load() -> Self {
		let raw_json = include_str!("../assets/signatures.json");
		let raw: SignatureDbRaw = serde_json::from_str(raw_json).expect("invalid signatures.json");
		let patterns = raw
			.signatures
			.into_iter()
			.filter_map(|s| {
				Regex::new(&format!("(?i){}", s.pattern)).ok().map(|re| (s.name, s.family, re))
			})
			.collect();
		Self { patterns }
	}
}

fn file_extension_lowercase(path: &Path) -> Option<String> {
	path.extension().map(|e| e.to_string_lossy().to_string().to_lowercase())
}

fn compute_sha256(bytes: &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(bytes);
	format!("{:x}", hasher.finalize())
}

fn should_scan(path: &Path, options: &ScanOptions) -> bool {
	if let Some(exts) = &options.include_extensions {
		if let Some(ext) = file_extension_lowercase(path) {
			return exts.iter().any(|e| e == &ext);
		} else {
			return false;
		}
	}
	true
}

fn run_heuristics(path: &Path, content: &str) -> Vec<Detection> {
	let mut detections = Vec::new();
	// Simple heuristic rules (illustrative, not exhaustive)
	let lowered = content.to_lowercase();
	let disable_rm = "disableRealtimeMonitoring".to_lowercase();
	let indicators: [&str; 13] = [
		"powershell -enc",
		"downloadstring(",
		"invoke-expression",
		"add-mppreference",
		disable_rm.as_str(),
		"reg add \\\\hklm\\software\\microsoft\\windows\\currentversion\\run",
		"schtasks /create",
		"wscript.shell",
		"system.net.webclient",
		"reflective loader",
		"keylogger",
		"clipboard",
		"rdp",
	];
	let hit = indicators.iter().any(|ind| lowered.contains(ind));
	if hit {
		detections.push(Detection {
			path: path.to_path_buf(),
			kind: DetectionKind::Heuristic {
				description: "Suspicious script or RAT-like behavior indicators".to_string(),
			},
			severity: 6,
			sha256: None,
		});
	}
	detections
}

pub fn scan_paths<P: AsRef<Path> + Send + Sync>(paths: &[P], options: ScanOptions) -> Vec<Detection> {
	let sigdb = SignatureDb::load();
	let candidates: Vec<PathBuf> = paths
		.par_iter()
		.flat_map_iter(|p| {
			WalkDir::new(p)
				.follow_links(false)
				.into_iter()
				.filter_map(Result::ok)
				.filter(|e| e.file_type().is_file())
				.map(|e| e.into_path())
				.collect::<Vec<_>>()
		})
		.filter(|p| should_scan(p, &options))
		.collect();

	candidates
		.par_iter()
		.filter_map(|path| {
			let meta = fs::metadata(path).ok()?;
			if meta.len() > options.max_file_size_bytes { return None; }
			let mut file = fs::File::open(path).ok()?;
			let mut buf = Vec::with_capacity(meta.len() as usize);
			if file.read_to_end(&mut buf).is_err() { return None; }

			// Attempt to read as text for regex matching. If not UTF-8, fall back to lossy
			let content = String::from_utf8_lossy(&buf);

			// Signature matches
			for (name, family, re) in &sigdb.patterns {
				if re.is_match(&content) {
					let sha = compute_sha256(&buf);
					return Some(Detection {
						path: path.clone(),
						kind: DetectionKind::Signature { name: name.clone(), family: family.clone() },
						severity: 8,
						sha256: Some(sha),
					});
				}
			}

			// Heuristics
			if options.enable_heuristics {
				let mut hs = run_heuristics(path, &content);
				if !hs.is_empty() { return hs.pop(); }
			}
			None
		})
		.collect()
}