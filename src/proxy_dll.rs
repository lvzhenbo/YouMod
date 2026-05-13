use crate::error::{Result, YouModError};
use std::path::Path;

const PROXY_DLL: &[u8] = include_bytes!(env!("PROXY_DLL_PATH"));

pub fn write_proxy_dll(dest_dir: &Path) -> Result<()> {
    let dest = dest_dir.join("version.dll");
    std::fs::write(&dest, PROXY_DLL).map_err(|e| YouModError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;
    Ok(())
}

pub fn remove_proxy_dll(dest_dir: &Path) -> Result<()> {
    let dest = dest_dir.join("version.dll");
    if dest.exists() {
        std::fs::remove_file(&dest).map_err(|e| YouModError::Io {
            path: dest.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}
