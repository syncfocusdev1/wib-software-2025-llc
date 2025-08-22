use anyhow::Result;
use rand::{distributions::Alphanumeric, Rng};
use wib_database::{init_db, DbConfig, Role, create_user_if_missing, authenticate_user};

#[test]
fn create_and_authenticate_user() -> Result<()> {
	let temp = tempfile::tempdir()?;
	let db_path = temp.path().join("accounts.db");
	let key: [u8; 32] = rand::random();
	let cfg = DbConfig { path: db_path.to_string_lossy().to_string(), key_256bit: key };
	let conn = init_db(&cfg)?;
	let email = "user@example.com";
	let password: String = rand::thread_rng().sample_iter(&Alphanumeric).take(12).map(char::from).collect();
	create_user_if_missing(&conn, &cfg, email, &password, Role::User)?;
	let auth = authenticate_user(&conn, &cfg, email, &password)?;
	assert!(auth.is_some());
	Ok(())
}