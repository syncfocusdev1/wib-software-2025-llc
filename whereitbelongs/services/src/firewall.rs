use anyhow::Result;

#[cfg(target_os = "windows")]
mod windows {
	use anyhow::Result;
	use std::process::Command;

	fn run(args: &[&str]) -> Result<()> {
		let _ = Command::new("netsh").args(args).output();
		Ok(())
	}

	pub fn block_domain(domain: &str) -> Result<()> {
		let rule_name = format!("WIB_Block_{}", domain);
		run(&["advfirewall","firewall","add","rule","name=", &rule_name, "dir=out","action=block","enable=yes","remoteip=any","remoteport=any"]) // domain blocking via netsh is limited; rely on DNS blocking elsewhere
	}

	pub fn block_ip(ip: &str) -> Result<()> {
		let rule_name = format!("WIB_BlockIP_{}", ip);
		run(&["advfirewall","firewall","add","rule","name=", &rule_name, "dir=out","action=block","enable=yes","remoteip=", ip])
	}

	pub fn enable_zero_trust() -> Result<()> {
		// Example: block all inbound by default
		run(&["advfirewall","set","allprofiles","firewallpolicy","blockinbound,allowoutbound"])
	}

	pub fn remove_rule(name: &str) -> Result<()> {
		run(&["advfirewall","firewall","delete","rule","name=", name])
	}
}

#[cfg(not(target_os = "windows"))]
mod windows {
	use anyhow::Result;
	pub fn block_domain(_domain: &str) -> Result<()> { Ok(()) }
	pub fn block_ip(_ip: &str) -> Result<()> { Ok(()) }
	pub fn enable_zero_trust() -> Result<()> { Ok(()) }
	pub fn remove_rule(_name: &str) -> Result<()> { Ok(()) }
}

pub use windows::*;