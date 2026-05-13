use crate::detector::WandInstallation;
use crate::error::{Result, YouModError};
use crate::patcher;
use crate::patches::PATCHES;
use crate::proxy_dll;
use asar_rust as asar;
use asar_rust::filesystem::FilesystemEntry;
use std::fs;
use std::path::PathBuf;

pub struct PatchStats {
    pub applied: Vec<String>,
    pub failed: Vec<String>,
}

/// 删除旧版本的结果
pub struct CleanupStats {
    pub deleted: Vec<String>,
}

use std::os::windows::process::CommandExt;

pub fn kill_wand(install: &WandInstallation) {
    let exe_stem = install
        .exe_path
        .file_stem()
        .map(|n| n.to_str().unwrap_or(""))
        .unwrap_or("");
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/IM", &format!("{}.exe", exe_stem)])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

fn copy_directory(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    if dst.exists() {
        fs::remove_dir_all(dst).map_err(|e| YouModError::Io {
            path: dst.display().to_string(),
            source: e,
        })?;
    }
    fs::create_dir_all(dst).map_err(|e| YouModError::Io {
        path: dst.display().to_string(),
        source: e,
    })?;
    copy_dir_recursive(src, dst)
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    for entry in fs::read_dir(src).map_err(|e| YouModError::Io {
        path: src.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| YouModError::Io {
            path: src.display().to_string(),
            source: e,
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            fs::create_dir_all(&dst_path).map_err(|e| YouModError::Io {
                path: dst_path.display().to_string(),
                source: e,
            })?;
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|e| YouModError::Io {
                path: dst_path.display().to_string(),
                source: e,
            })?;
        }
    }
    Ok(())
}

pub struct PatchConfig {
    pub pro: bool,
    pub disable_updates: bool,
}

pub fn apply_patches(install: &WandInstallation, config: &PatchConfig) -> Result<PatchStats> {
    kill_wand(install);

    // If backup exists, restore pristine app.asar before patching
    if install.asar_backup_path.exists() {
        fs::copy(&install.asar_backup_path, &install.asar_path).map_err(|e| YouModError::Io {
            path: install.asar_path.display().to_string(),
            source: e,
        })?;
    } else {
        fs::copy(&install.asar_path, &install.asar_backup_path).map_err(|e| YouModError::Io {
            path: install.asar_backup_path.display().to_string(),
            source: e,
        })?;
    }

    let unpacked = unpacked_dir_for(&install.asar_path)?;

    // If unpacked backup exists, restore pristine unpacked dir
    if install.asar_unpacked_backup_path.exists() {
        copy_directory(&install.asar_unpacked_backup_path, &unpacked)?;
    } else if unpacked.exists() {
        copy_directory(&unpacked, &install.asar_unpacked_backup_path)?;
    } else {
        // Fresh install — neither backup nor unpacked dir exists
        fs::create_dir_all(&unpacked).map_err(|e| YouModError::Io {
            path: unpacked.display().to_string(),
            source: e,
        })?;
    }

    extract_asar(install, &unpacked)?;

    let filtered: Vec<&crate::patches::JsPatch> = PATCHES
        .iter()
        .filter(|p| {
            (p.kind == crate::patches::PatchKind::ProSpoof && config.pro)
                || (p.kind == crate::patches::PatchKind::DisableUpdates && config.disable_updates)
        })
        .collect();

    let result = patcher::patch_js_files(&unpacked, filtered.as_slice())?;

    repack_asar(&unpacked, &install.asar_path)?;

    proxy_dll::write_proxy_dll(&install.root_dir)?;

    Ok(PatchStats {
        applied: result.applied,
        failed: result.failed,
    })
}

pub fn is_patched(install: &WandInstallation) -> bool {
    if !install.asar_backup_path.exists() {
        return false;
    }
    // Fast path: compare file sizes — patched ASAR almost always differs in size
    let Ok(current_meta) = std::fs::metadata(&install.asar_path) else {
        return false;
    };
    let Ok(backup_meta) = std::fs::metadata(&install.asar_backup_path) else {
        return false;
    };
    if current_meta.len() != backup_meta.len() {
        return true;
    }
    // Slow path: sizes match (unlikely), fall back to full byte comparison
    let Ok(current) = std::fs::read(&install.asar_path) else {
        return false;
    };
    let Ok(backup) = std::fs::read(&install.asar_backup_path) else {
        return false;
    };
    current != backup
}

pub fn restore(install: &WandInstallation) -> Result<()> {
    kill_wand(install);
    if install.asar_backup_path.exists() {
        fs::copy(&install.asar_backup_path, &install.asar_path).map_err(|e| YouModError::Io {
            path: install.asar_path.display().to_string(),
            source: e,
        })?;
    }
    proxy_dll::remove_proxy_dll(&install.root_dir)?;
    Ok(())
}

/// 一键删除所有旧版本，保留最新版本
pub fn delete_old_versions() -> Result<CleanupStats> {
    use crate::detector::{find_all_installations, find_old_installations};

    // 先终止 Wand 进程，避免文件占用
    let all = find_all_installations();
    for inst in &all {
        kill_wand(inst);
    }

    let old = find_old_installations();
    let mut deleted = Vec::new();

    for inst in &old {
        match fs::remove_dir_all(&inst.root_dir) {
            Ok(()) => {
                let name = inst
                    .root_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| inst.root_dir.display().to_string());
                deleted.push(name);
            }
            Err(e) => {
                return Err(YouModError::Io {
                    path: inst.root_dir.display().to_string(),
                    source: e,
                });
            }
        }
    }

    Ok(CleanupStats { deleted })
}

fn unpacked_dir_for(asar_path: &std::path::Path) -> Result<PathBuf> {
    let parent = asar_path
        .parent()
        .ok_or_else(|| YouModError::Other(anyhow::anyhow!("asar_path has no parent")))?;
    Ok(parent.join("app.asar.unpacked"))
}

fn extract_asar(install: &WandInstallation, dest: &std::path::Path) -> Result<()> {
    let archive = asar::AsarArchive::open(&install.asar_path).map_err(|e| YouModError::AsarOp {
        op: "extract",
        source: e.into(),
    })?;

    let files = archive.list().map_err(|e| YouModError::AsarOp {
        op: "extract",
        source: e.into(),
    })?;

    let unpacked_dir = format!("{}.unpacked", install.asar_path.display());

    for full_path in &files {
        let filename = &full_path[1..];
        let dest_path = dest.join(filename);

        let entry = archive
            .stat(filename, cfg!(windows))
            .map_err(|e| YouModError::AsarOp {
                op: "extract",
                source: e.into(),
            })?;

        match entry {
            FilesystemEntry::Directory(_) => {
                fs::create_dir_all(&dest_path).map_err(|e| YouModError::Io {
                    path: dest_path.display().to_string(),
                    source: e,
                })?;
            }
            FilesystemEntry::Link(_) => {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| YouModError::Io {
                        path: parent.display().to_string(),
                        source: e,
                    })?;
                }
            }
            FilesystemEntry::File(file_info) => {
                if file_info.unpacked {
                    let source = std::path::Path::new(&unpacked_dir).join(filename);
                    if source == dest_path {
                        continue;
                    }
                    if !source.exists() {
                        continue;
                    }
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent).map_err(|e| YouModError::Io {
                            path: parent.display().to_string(),
                            source: e,
                        })?;
                    }
                    fs::copy(&source, &dest_path).map_err(|e| YouModError::Io {
                        path: dest_path.display().to_string(),
                        source: e,
                    })?;
                } else {
                    let data = archive
                        .extract_file(filename)
                        .map_err(|e| YouModError::AsarOp {
                            op: "extract",
                            source: e.into(),
                        })?;
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent).map_err(|e| YouModError::Io {
                            path: parent.display().to_string(),
                            source: e,
                        })?;
                    }
                    fs::write(&dest_path, data).map_err(|e| YouModError::Io {
                        path: dest_path.display().to_string(),
                        source: e,
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn repack_asar(unpacked_dir: &std::path::Path, dest_asar: &std::path::Path) -> Result<()> {
    let options = asar::CreateOptions {
        dot: false,
        ordering: None,
        unpack: Some(r"^static[/\\]unpacked.*$".to_string()),
        unpack_dir: None,
    };
    asar::create_package_with_options(unpacked_dir, dest_asar, options).map_err(|e| {
        YouModError::AsarOp {
            op: "repack",
            source: e.into(),
        }
    })?;
    Ok(())
}
