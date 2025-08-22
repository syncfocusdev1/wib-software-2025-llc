use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
	pub version: String,
	pub notes: Option<String>,
	pub url: String,
	pub sha256: Option<String>,
}

pub async fn fetch_manifest(url: &str) -> Result<UpdateManifest> {
	let body = reqwest::get(url).await?.text().await?;
	let m: UpdateManifest = serde_json::from_str(&body).context("parse manifest")?;
	Ok(m)
}

pub async fn download_update(url: &str) -> Result<Vec<u8>> {
	let bytes = reqwest::get(url).await?.bytes().await?;
	Ok(bytes.to_vec())
}