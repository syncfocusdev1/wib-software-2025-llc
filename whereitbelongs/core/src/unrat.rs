use anyhow::Result;

#[cfg(target_os = "windows")]
mod windows {
	use anyhow::{anyhow, Context, Result};
	use std::process::Command;

	pub fn kill_known_rat_processes() -> Result<()> {
		let suspects = ["njrat", "quasar", "remcos", "asyncrat", "warzone", "nanocore", "darkcomet", "blackshades"];
		for name in suspects {
			let _ = Command::new("taskkill").args(["/F", "/IM", &format!("{}.exe", name)]).output();
		}
		Ok(())
	}

	pub fn purge_run_keys() -> Result<()> {
		// Remove common persistence in Run keys
		let keys = [
			"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		];
		for key in keys {
			let _ = Command::new("reg").args(["delete", key, "/f"]).output();
		}
		Ok(())
	}

	pub fn remove_suspicious_schtasks() -> Result<()> {
		// Try to delete tasks known for RATs (wildcard)
		let _ = Command::new("schtasks").args(["/Query", "/FO", "LIST"]).output();
		// Without enumerating, at least attempt cleanup by common names
		for name in ["Updater", "WindowsUpdater", "AdobeUpdate", "SystemCheck", "ChromeUpdate"] {
			let _ = Command::new("schtasks").args(["/Delete", "/TN", name, "/F"]).output();
		}
		Ok(())
	}

	pub fn clear_wmi_persistence() -> Result<()> {
		// Attempt to reset WMI subscription persistence (requires admin)
		let _ = Command::new("powershell")
			.args([
				"-NoProfile",
				"-ExecutionPolicy","Bypass",
				"-Command",
				"Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Remove-WmiObject -ErrorAction SilentlyContinue; \
				Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Remove-WmiObject -ErrorAction SilentlyContinue; \
				Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Remove-WmiObject -ErrorAction SilentlyContinue;"
			])
			.output();
		Ok(())
	}

	pub fn one_click_recovery() -> Result<()> {
		kill_known_rat_processes()?;
		purge_run_keys()?;
		remove_suspicious_schtasks()?;
		clear_wmi_persistence()?;
		Ok(())
	}
}

#[cfg(not(target_os = "windows"))]
mod windows {
	use anyhow::Result;
	pub fn kill_known_rat_processes() -> Result<()> { Ok(()) }
	pub fn purge_run_keys() -> Result<()> { Ok(()) }
	pub fn remove_suspicious_schtasks() -> Result<()> { Ok(()) }
	pub fn clear_wmi_persistence() -> Result<()> { Ok(()) }
	pub fn one_click_recovery() -> Result<()> { Ok(()) }
}

pub use windows::*;

pub fn memory_purge() -> Result<()> {
	// Placeholder for clearing caches; cross-platform safe no-op
	Ok(())
}