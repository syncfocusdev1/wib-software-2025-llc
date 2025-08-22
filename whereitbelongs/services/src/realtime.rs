use anyhow::Result;
use crossbeam_channel::unbounded;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use wib_core::{scan_paths, Detection, ScanOptions};

#[derive(Clone, Debug)]
pub struct RealtimeOptions {
	pub paths: Vec<PathBuf>,
}

pub struct RealtimeGuard {
	_join: thread::JoinHandle<()>,
}

pub fn start_realtime(opts: RealtimeOptions, tx_detect: crossbeam_channel::Sender<Detection>) -> Result<RealtimeGuard> {
	let (tx, rx) = unbounded();
	let mut watcher: RecommendedWatcher = RecommendedWatcher::new(move |res| {
		let _ = tx.send(res);
	}, Config::default())?;
	for p in &opts.paths {
		watcher.watch(p, RecursiveMode::Recursive)?;
	}
	let handle = thread::spawn(move || {
		let scan_opts = ScanOptions::default();
		loop {
			match rx.recv_timeout(Duration::from_millis(500)) {
				Ok(Ok(Event { kind: EventKind::Create(_) | EventKind::Modify(_), paths, .. })) => {
					for p in paths {
						let ds = scan_paths(&[p.clone()], scan_opts.clone());
						for d in ds { let _ = tx_detect.send(d); }
					}
				}
				_ => {}
			}
		}
	});
	Ok(RealtimeGuard { _join: handle })
}