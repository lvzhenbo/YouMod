//! Static patching of Electron "fuses" directly inside the packaged exe.
//!
//! `Wand.exe` is built with `DependentLoadFlags=0x0800`
//! (`LOAD_LIBRARY_SEARCH_SYSTEM32`), which confines the search for *static
//! imports* to `System32`. A local `version.dll` proxy is therefore never
//! loaded, so the ASAR integrity check cannot be disabled from inside a
//! hijacked DLL at process-attach time.
//!
//! Instead we flip the `EnableEmbeddedAsarIntegrityValidation` fuse byte in the
//! exe file itself. Electron reads this fuse through
//! `IsEmbeddedAsarIntegrityValidationEnabled()`, which evaluates to
//! `kFuseWire[index] == '1'` — so writing any byte other than `'1'`
//! (canonically `'0'`) disables the check before `app.asar` is ever read.

use crate::error::{Result, YouModError};
use std::fs;
use std::path::Path;

/// Exact sentinel from `@electron/fuses` (`src/constants.ts`).
const SENTINEL: &[u8; 32] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

/// Byte immediately after the sentinel is the fuse wire version (always 1).
const FUSE_VERSION_SUPPORTED: u8 = 1;

/// `FuseV1Options::EnableEmbeddedAsarIntegrityValidation`.
const FUSE_ASAR_INTEGRITY_VALIDATION: usize = 4;

/// Wire byte value Electron treats as "disabled" (`FuseState.DISABLE` = `'0'`).
const FUSE_DISABLED: u8 = b'0';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseOutcome {
    /// Validation was enabled; the fuse has been flipped off.
    Disabled,
    /// Validation was already off; the exe was left untouched.
    AlreadyDisabled,
    /// The fuse wire could not be located in the exe.
    NotFound,
}

fn find_sentinels(bytes: &[u8]) -> Vec<usize> {
    bytes
        .windows(SENTINEL.len())
        .enumerate()
        .filter_map(|(i, w)| if w == SENTINEL { Some(i) } else { None })
        .collect()
}

/// Disables embedded ASAR integrity validation by flipping the fuse in-place.
///
/// Idempotent: if a backup exists it is restored first, then the flip is
/// re-applied. Returns [`FuseOutcome::Disabled`] only when the file actually
/// changed; a pristine backup is written before the first modification.
pub fn patch_asar_integrity_fuse(exe_path: &Path, backup_path: &Path) -> Result<FuseOutcome> {
    if backup_path.exists() {
        fs::copy(backup_path, exe_path).map_err(|e| YouModError::Io {
            path: exe_path.display().to_string(),
            source: e,
        })?;
    }

    let bytes = fs::read(exe_path).map_err(|e| YouModError::Io {
        path: exe_path.display().to_string(),
        source: e,
    })?;

    let offsets = find_sentinels(&bytes);
    if offsets.is_empty() {
        return Ok(FuseOutcome::NotFound);
    }

    let mut changes = Vec::new();
    for &off in &offsets {
        let header = off + SENTINEL.len();
        let version = *bytes
            .get(header)
            .ok_or_else(|| YouModError::Other(anyhow::anyhow!("fuse wire header is truncated")))?;
        if version != FUSE_VERSION_SUPPORTED {
            return Ok(FuseOutcome::NotFound);
        }
        let wire_len = *bytes
            .get(header + 1)
            .ok_or_else(|| YouModError::Other(anyhow::anyhow!("fuse wire length is truncated")))?;
        if (wire_len as usize) <= FUSE_ASAR_INTEGRITY_VALIDATION {
            // Wire too short to carry this fuse; nothing to flip.
            continue;
        }
        let target = header + 2 + FUSE_ASAR_INTEGRITY_VALIDATION;
        if bytes[target] != FUSE_DISABLED {
            changes.push(target);
        }
    }

    if changes.is_empty() {
        return Ok(FuseOutcome::AlreadyDisabled);
    }

    if !backup_path.exists() {
        fs::write(backup_path, &bytes).map_err(|e| YouModError::Io {
            path: backup_path.display().to_string(),
            source: e,
        })?;
    }

    let mut patched = bytes;
    for target in changes {
        patched[target] = FUSE_DISABLED;
    }

    fs::write(exe_path, &patched).map_err(|e| YouModError::Io {
        path: exe_path.display().to_string(),
        source: e,
    })?;

    Ok(FuseOutcome::Disabled)
}

/// Restores the pristine exe from the backup, if one exists.
pub fn restore_exe(exe_path: &Path, backup_path: &Path) -> Result<()> {
    if backup_path.exists() {
        fs::copy(backup_path, exe_path).map_err(|e| YouModError::Io {
            path: exe_path.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}
