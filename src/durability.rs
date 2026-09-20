//! The durability program's invocation surface: where the console
//! finds `unidpp-ops` and how it speaks to it. The program lives in
//! the deployment's ops-tools crate (the retired root script's
//! successor); the resolved path is computed once per call and every
//! backups surface goes through it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The durability program beside a deployment root: the ops-tools
/// release binary, the debug binary, or (before a deployment's
/// cutover) the retired root script.
pub fn unidpp_ops(root: &Path) -> Option<PathBuf> {
    [
        root.join("ops-tools/target/release/unidpp-ops"),
        root.join("ops-tools/target/debug/unidpp-ops"),
        root.join("unidpp-ops"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// A command that runs the durability program from the deployment
/// root (its archives, journals and manifests are root-relative).
/// Panics never: a missing program surfaces as a spawn error the
/// callers render.
pub fn command(root: &Path) -> Command {
    let mut command = Command::new(
        unidpp_ops(root).unwrap_or_else(|| root.join("ops-tools/target/release/unidpp-ops")),
    );
    command.current_dir(root);
    command
}
