pub mod scan;
pub mod quarantine;
pub mod unrat;

pub use scan::{scan_paths, Detection, DetectionKind, ScanOptions};