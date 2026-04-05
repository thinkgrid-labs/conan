use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

/// Persisted state written to `~/.conan/scan_state.json` after each `--diff` scan.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScanState {
    /// Short git commit hash at the time of the last scan.
    pub last_commit: Option<String>,
    /// File → mtime (nanos since UNIX epoch) at the time of the last scan.
    /// Used as a fallback when git is not available.
    #[serde(default)]
    pub mtimes: HashMap<String, u128>,
}

impl ScanState {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("scan_state.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
        let path = data_dir.join("scan_state.json");
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Returns the current HEAD short commit hash, or `None` if not in a git repo.
pub fn current_commit(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap_or("."),
            "rev-parse",
            "--short",
            "HEAD",
        ])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the set of absolute file paths that changed since the last scan.
///
/// Strategy (in order):
/// 1. `git diff --name-only <last_commit> HEAD` if we have a previous commit.
/// 2. `git ls-files` for a first-ever scan in a git repo (all tracked files).
/// 3. mtime comparison against `state.mtimes` as a fallback for non-git dirs.
pub fn changed_files(root: &Path, state: &ScanState, commit: Option<&str>) -> HashSet<PathBuf> {
    if let Some(ref last) = state.last_commit {
        if let Some(rel_paths) = git_diff_files(root, last) {
            return rel_paths.into_iter().map(|p| root.join(p)).collect();
        }
    }

    // First-ever --diff run in a git repo: treat all tracked files as changed.
    if commit.is_some() {
        if let Some(rel_paths) = git_ls_files(root) {
            return rel_paths.into_iter().map(|p| root.join(p)).collect();
        }
    }

    // Non-git fallback: return files whose mtime is newer than the snapshot.
    mtime_changed_files(root, state)
}

/// Snapshot current mtimes for every file under `root`.
pub fn snapshot_mtimes(root: &Path) -> HashMap<String, u128> {
    let mut map = HashMap::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let key = entry.path().to_string_lossy().to_string();
        let mtime = mtime_nanos(entry.path());
        map.insert(key, mtime);
    }
    map
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn git_diff_files(root: &Path, since: &str) -> Option<Vec<PathBuf>> {
    let out = std::process::Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap_or("."),
            "diff",
            "--name-only",
            since,
            "HEAD",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_paths(&out.stdout))
}

fn git_ls_files(root: &Path) -> Option<Vec<PathBuf>> {
    let out = std::process::Command::new("git")
        .args(["-C", root.to_str().unwrap_or("."), "ls-files"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_paths(&out.stdout))
}

fn parse_paths(bytes: &[u8]) -> Vec<PathBuf> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn mtime_changed_files(root: &Path, state: &ScanState) -> HashSet<PathBuf> {
    let mut changed = HashSet::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let key = path.to_string_lossy().to_string();
        let mtime = mtime_nanos(path);
        let last = state.mtimes.get(&key).copied().unwrap_or(0);
        if mtime > last {
            changed.insert(path.to_path_buf());
        }
    }
    changed
}

fn mtime_nanos(path: &Path) -> u128 {
    path.metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
