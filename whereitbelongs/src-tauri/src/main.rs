#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::State;
use wib_core::{scan_paths, ScanOptions};
use wib_core::unrat as unrat_core;
use wib_database::{init_db, DbConfig, ensure_default_superadmin, authenticate_user, Role};

struct AppState {
	db_path: String,
	db_key: [u8; 32],
}

#[derive(Serialize)]
struct ScanResponse { detections: usize }

#[tauri::command]
fn cmd_scan(paths: Vec<String>) -> Result<ScanResponse, String> {
	let p: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
	let res = scan_paths(&p, ScanOptions::default());
	Ok(ScanResponse { detections: res.len() })
}

#[tauri::command]
fn cmd_unrat_recover() -> Result<(), String> {
	unrat_core::one_click_recovery().map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct LoginRequest { email: String, password: String }

#[derive(Serialize)]
struct LoginResponse { ok: bool, role: Option<String> }

#[tauri::command]
fn cmd_login(state: State<AppState>, req: LoginRequest) -> Result<LoginResponse, String> {
	let cfg = DbConfig { path: state.db_path.clone(), key_256bit: state.db_key };
	let conn = init_db(&cfg).map_err(|e| e.to_string())?;
	ensure_default_superadmin(&conn, &cfg).map_err(|e| e.to_string())?;
	let auth = authenticate_user(&conn, &cfg, &req.email, &req.password).map_err(|e| e.to_string())?;
	if let Some(acc) = auth {
		Ok(LoginResponse { ok: true, role: Some(format!("{:?}", acc.role)) })
	} else {
		Ok(LoginResponse { ok: false, role: None })
	}
}

fn main() {
	let db_dir = std::env::var("WIB_DATA_DIR").unwrap_or_else(|_| {
		let d = dirs::data_dir().unwrap_or(std::env::temp_dir());
		d.join("whereitbelongs").to_string_lossy().to_string()
	});
	std::fs::create_dir_all(&db_dir).ok();
	let db_path = format!("{}/accounts.db", db_dir.trim_end_matches('/'));
	let key: [u8; 32] = [7u8; 32];

	tauri::Builder::default()
		.manage(AppState { db_path, db_key: key })
		.invoke_handler(tauri::generate_handler![cmd_scan, cmd_unrat_recover, cmd_login])
		.run(tauri::generate_context!())
		.expect("error while running tauri application");
}