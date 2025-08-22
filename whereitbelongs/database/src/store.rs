use crate::models::{Role, UserAccount};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use rand::RngCore;
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Clone)]
pub struct DbConfig {
	pub path: String,
	pub key_256bit: [u8; 32],
}

fn to_role_str(role: &Role) -> &'static str {
	match role {
		Role::SuperAdmin => "SuperAdmin",
		Role::Admin => "Admin",
		Role::PowerUser => "PowerUser",
		Role::User => "User",
	}
}

fn from_role_str(s: &str) -> Result<Role> {
	Ok(match s {
		"SuperAdmin" => Role::SuperAdmin,
		"Admin" => Role::Admin,
		"PowerUser" => Role::PowerUser,
		"User" => Role::User,
		_ => return Err(anyhow!("invalid role")),
	})
}

pub fn init_db(cfg: &DbConfig) -> Result<Connection> {
	let path = Path::new(&cfg.path);
	if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
	let conn = Connection::open(path).with_context(|| format!("open db {}", cfg.path))?;
	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email_encrypted_b64 TEXT NOT NULL,
			email_nonce_b64 TEXT NOT NULL,
			email_lookup_b64 TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);",
	)?;
	// ensure column exists if upgrading from an older schema
	let _ = conn.execute("ALTER TABLE users ADD COLUMN email_lookup_b64 TEXT NOT NULL DEFAULT ''", []);
	Ok(conn)
}

fn encrypt_email(key: &[u8; 32], email: &str) -> Result<(String, String)> {
	let cipher = Aes256Gcm::new_from_slice(key).expect("key");
	let mut nonce_bytes = [0u8; 12];
	OsRng.fill_bytes(&mut nonce_bytes);
	let nonce = Nonce::from_slice(&nonce_bytes);
	let ciphertext = cipher.encrypt(nonce, email.as_bytes()).map_err(|_| anyhow!("encrypt"))?;
	Ok((general_purpose::STANDARD.encode(ciphertext), general_purpose::STANDARD.encode(nonce_bytes)))
}

fn decrypt_email(key: &[u8; 32], enc_b64: &str, nonce_b64: &str) -> Result<String> {
	let cipher = Aes256Gcm::new_from_slice(key).expect("key");
	let nonce_raw = general_purpose::STANDARD.decode(nonce_b64)?;
	let nonce = Nonce::from_slice(&nonce_raw);
	let ct = general_purpose::STANDARD.decode(enc_b64)?;
	let pt = cipher.decrypt(nonce, ct.as_ref()).map_err(|_| anyhow!("decrypt"))?;
	Ok(String::from_utf8(pt).map_err(|_| anyhow!("utf8"))?)
}

pub fn create_user_if_missing(conn: &Connection, cfg: &DbConfig, email: &str, password: &str, role: Role) -> Result<()> {
	let lookup = email_lookup_key(cfg, email)?;
	let exists: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM users WHERE email_lookup_b64 = ?)",
		params![lookup],
		|row| row.get::<_, i64>(0),
	).unwrap_or(0) == 1;
	if exists { return Ok(()); }

	let (email_ct_b64, nonce_b64) = encrypt_email(&cfg.key_256bit, email)?;
	let password_hash = hash_password(password)?;
	let created_at = Utc::now().timestamp();
	let role_str = to_role_str(&role);
	conn.execute(
		"INSERT INTO users (email_encrypted_b64, email_nonce_b64, email_lookup_b64, password_hash, role, created_at) VALUES (?,?,?,?,?,?)",
		params![email_ct_b64, nonce_b64, lookup, password_hash, role_str, created_at],
	)?;
	Ok(())
}

fn email_lookup_key(cfg: &DbConfig, email: &str) -> Result<String> {
	// Deterministic encrypted value for existence/auth lookup by using fixed nonce of zeros
	let cipher = Aes256Gcm::new_from_slice(&cfg.key_256bit).expect("key");
	let nonce = Nonce::from_slice(&[0u8; 12]);
	let ct = cipher.encrypt(nonce, email.as_bytes()).map_err(|_| anyhow!("encrypt"))?;
	Ok(general_purpose::STANDARD.encode(ct))
}

fn hash_password(password: &str) -> Result<String> {
	let argon = Argon2::default();
	let salt = SaltString::generate(&mut rand::thread_rng());
	let hash = argon.hash_password(password.as_bytes(), &salt)?.to_string();
	Ok(hash)
}

fn verify_password(password: &str, hash: &str) -> Result<bool> {
	let parsed = PasswordHash::new(hash)?;
	Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

pub fn authenticate_user(conn: &Connection, cfg: &DbConfig, email: &str, password: &str) -> Result<Option<UserAccount>> {
	let lookup = email_lookup_key(cfg, email)?;
	let mut stmt = conn.prepare(
		"SELECT id, email_encrypted_b64, email_nonce_b64, password_hash, role, created_at FROM users WHERE email_lookup_b64 = ?"
	)?;
	let mut rows = stmt.query(params![lookup])?;
	if let Some(row) = rows.next()? {
		let email_ct_b64: String = row.get(1)?;
		let nonce_b64: String = row.get(2)?;
		let _decrypted = decrypt_email(&cfg.key_256bit, &email_ct_b64, &nonce_b64).unwrap_or_default();
		let hash: String = row.get(3)?;
		if verify_password(password, &hash)? {
			let role_str: String = row.get(4)?;
			let role = from_role_str(&role_str)?;
			return Ok(Some(UserAccount {
				id: row.get(0)?,
				email_encrypted_b64: email_ct_b64,
				email_nonce_b64: nonce_b64,
				password_hash: hash,
				role,
				created_at: row.get(5)?,
			}));
		}
	}
	Ok(None)
}

pub fn ensure_default_superadmin(conn: &Connection, cfg: &DbConfig) -> Result<()> {
	create_user_if_missing(conn, cfg, "kevin@wib.gg", "kevinisthegoat69", Role::SuperAdmin)
}