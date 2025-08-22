use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn app_data_dir() -> PathBuf {
	if let Ok(p) = std::env::var("WIB_DATA_DIR") {
		return PathBuf::from(p);
	}
	let base = dirs::data_dir().unwrap_or(std::env::temp_dir());
	base.join("whereitbelongs")
}

fn ensure_dir(dir: &Path) -> Result<()> {
	fs::create_dir_all(dir).with_context(|| format!("Failed to create dir: {}", dir.display()))
}

fn sha256_of(bytes: &[u8]) -> String {
	let mut h = Sha256::new();
	h.update(bytes);
	format!("{:x}", h.finalize())
}

pub fn quarantine_file<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
	let path = path.as_ref();
	let mut f = fs::File::open(path)
		.with_context(|| format!("Failed to open {}", path.display()))?;
	let mut buf = Vec::new();
	f.read_to_end(&mut buf)?;
	let sha = sha256_of(&buf);
	let qdir = app_data_dir().join("quarantine");
	ensure_dir(&qdir)?;
	let qpath = qdir.join(format!("{}.qf", sha));
	let mut out = fs::File::create(&qpath)?;
	out.write_all(&buf)?;
	fs::remove_file(path).ok();
	Ok(qpath)
}

pub fn restore_from_quarantine<P: AsRef<Path>>(quarantined_path: P, restore_to: P) -> Result<()> {
	let quarantined_path = quarantined_path.as_ref();
	let restore_to = restore_to.as_ref();
	let data = fs::read(quarantined_path)?;
	fs::write(restore_to, data)?;
	Ok(())
}

pub fn list_quarantined() -> Result<Vec<PathBuf>> {
	let qdir = app_data_dir().join("quarantine");
	if !qdir.exists() { return Ok(Vec::new()); }
	let mut items = Vec::new();
	for entry in fs::read_dir(qdir)? {
		let e = entry?;
		if e.file_type()?.is_file() {
			items.push(e.path());
		}
	}
	Ok(items)
}