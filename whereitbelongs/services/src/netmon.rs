use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEvent {
	pub timestamp_ms: i64,
	pub description: String,
}

pub struct NetworkMonitor {
	_join: thread::JoinHandle<()>,
}

pub fn start(tx: crossbeam_channel::Sender<NetEvent>) -> NetworkMonitor {
	let handle = thread::spawn(move || {
		loop {
			let ts = chrono::Utc::now().timestamp_millis();
			let _ = tx.send(NetEvent { timestamp_ms: ts, description: "Heartbeat".into() });
			thread::sleep(Duration::from_secs(5));
		}
	});
	NetworkMonitor { _join: handle }
}