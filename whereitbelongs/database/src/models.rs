use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
	SuperAdmin,
	Admin,
	PowerUser,
	User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
	pub id: i64,
	pub email_encrypted_b64: String,
	pub email_nonce_b64: String,
	pub password_hash: String,
	pub role: Role,
	pub created_at: i64,
}