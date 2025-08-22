# WhereItBelongs (WIB)

A modern, modular antivirus and anti-RAT suite with a Rust core and a Tauri + Vue 3 desktop UI.

This repository hosts the Rust core engine, database/auth layer, background services, and the UI application.

## Status

- Initial scaffolding for Rust workspace (core, database, services)
- UI (Tauri + Vue 3) to be added next

## Build (Rust crates)

```bash
cd whereitbelongs
cargo build
```

## Crates

- `core`: scanning engine, UNRAT utilities, quarantine
- `database`: encrypted account store (AES-256-GCM) with Argon2 authentication
- `services`: realtime monitor, basic network monitor, firewall facade

## License

Dual-licensed under Apache-2.0 and MIT.