use crate::error::{Result, YouModError};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct WandInstallation {
    pub root_dir: PathBuf,
    pub exe_path: PathBuf,
    pub exe_backup_path: PathBuf,
    pub asar_path: PathBuf,
    pub asar_backup_path: PathBuf,
    pub asar_unpacked_backup_path: PathBuf,
    pub brand_name: String,
}

pub fn detect_wand() -> Result<WandInstallation> {
    let local_app_data = dirs::data_local_dir().ok_or(YouModError::WandNotFound)?;

    for brand in &["Wand", "WeMod"] {
        let brand_dir = local_app_data.join(brand);
        if !brand_dir.is_dir() {
            continue;
        }

        if let Some(install) = find_latest_app_dir(&brand_dir, brand) {
            return Ok(install);
        }
    }

    Err(YouModError::WandNotFound)
}

/// 返回所有已安装版本，按版本从新到旧排列
pub fn find_all_installations() -> Vec<WandInstallation> {
    let mut all = Vec::new();
    if let Some(local_app_data) = dirs::data_local_dir() {
        for brand in &["Wand", "WeMod"] {
            let brand_dir = local_app_data.join(brand);
            if brand_dir.is_dir() {
                all.extend(find_all_app_dirs(&brand_dir, brand));
            }
        }
    }
    // 按版本降序排列（最新在前）
    all.sort_by(|a, b| {
        let key_a = version_sort_key_from_path(&a.root_dir);
        let key_b = version_sort_key_from_path(&b.root_dir);
        key_b.cmp(&key_a)
    });
    all
}

/// 返回旧版本安装列表（除最新版本外的所有版本）
pub fn find_old_installations() -> Vec<WandInstallation> {
    let all = find_all_installations();
    if all.len() <= 1 {
        return Vec::new();
    }
    all.into_iter().skip(1).collect()
}

/// Resolves the packaged Electron executable inside an `app-*` directory.
///
/// The app is named `Wand.exe` even when installed under the `WeMod` folder
/// (`WeMod.exe` is only a small Squirrel stub that spawns it). Prefer
/// `Wand.exe`, falling back to `{brand}.exe` for any legacy layout.
fn resolve_exe(app_dir: &Path, brand: &str) -> Option<PathBuf> {
    let wand = app_dir.join("Wand.exe");
    if wand.is_file() {
        return Some(wand);
    }
    let branded = app_dir.join(format!("{}.exe", brand));
    if branded.is_file() {
        return Some(branded);
    }
    None
}

fn exe_backup_for(exe_path: &Path) -> PathBuf {
    let name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Wand.exe");
    exe_path.with_file_name(format!("{}.backup", name))
}

fn find_latest_app_dir(brand_dir: &Path, brand: &str) -> Option<WandInstallation> {
    let mut best: Option<(PathBuf, PathBuf, Vec<u64>)> = None;

    for entry in std::fs::read_dir(brand_dir).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name_str = name.to_str()?;

        if !name_str.starts_with("app-") {
            continue;
        }

        let version_str = &name_str[4..];
        let sort_key = parse_version_sort_key(version_str);

        let app_dir = entry.path();
        let Some(exe_path) = resolve_exe(&app_dir, brand) else {
            continue;
        };

        match &best {
            Some((_, _, best_key)) if sort_key <= *best_key => continue,
            _ => {}
        }

        let resources = app_dir.join("resources");
        if !resources.join("app.asar").is_file() {
            continue;
        }

        best = Some((app_dir, exe_path, sort_key));
    }

    best.map(|(app_dir, exe_path, _)| {
        let exe_backup_path = exe_backup_for(&exe_path);
        let resources = app_dir.join("resources");
        WandInstallation {
            root_dir: app_dir,
            exe_path,
            exe_backup_path,
            asar_path: resources.join("app.asar"),
            asar_backup_path: resources.join("app.asar.backup"),
            asar_unpacked_backup_path: resources.join("app.asar.unpacked.backup"),
            brand_name: brand.to_string(),
        }
    })
}

/// 查找某个品牌目录下的所有 app-* 安装
fn find_all_app_dirs(brand_dir: &Path, brand: &str) -> Vec<WandInstallation> {
    let mut installs = Vec::new();

    let dir_iter = match std::fs::read_dir(brand_dir) {
        Ok(it) => it,
        Err(_) => return installs,
    };

    for entry in dir_iter.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };

        if !name_str.starts_with("app-") {
            continue;
        }

        let app_dir = entry.path();
        let Some(exe_path) = resolve_exe(&app_dir, brand) else {
            continue;
        };

        let resources = app_dir.join("resources");
        if !resources.join("app.asar").is_file() {
            continue;
        }

        let exe_backup_path = exe_backup_for(&exe_path);
        installs.push(WandInstallation {
            root_dir: app_dir.clone(),
            exe_path,
            exe_backup_path,
            asar_path: resources.join("app.asar"),
            asar_backup_path: resources.join("app.asar.backup"),
            asar_unpacked_backup_path: resources.join("app.asar.unpacked.backup"),
            brand_name: brand.to_string(),
        });
    }

    installs
}

/// 从 app-{version} 目录路径中提取版本排序键
fn version_sort_key_from_path(path: &Path) -> Vec<u64> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with("app-") {
        parse_version_sort_key(&name[4..])
    } else {
        vec![0]
    }
}

fn parse_version_sort_key(version: &str) -> Vec<u64> {
    version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_sort_key() {
        let v1 = parse_version_sort_key("9.0.0");
        let v2 = parse_version_sort_key("10.0.0");
        let v3 = parse_version_sort_key("9.10.0");
        assert!(v2 > v1);
        assert!(v3 > v1);
        assert!(v2 > v3);
    }
}
