//! Refresh the SHA256 Wand bakes into `Wand.exe`'s `ElectronAsar\Integrity` PE
//! resource after `app.asar` has been repacked.
//!
//! A port of Wand-Enhancer's `AsarHeaderHash` + `AsarIntegrityResourcePatch`
//! (PR #318). The resource holds small UTF-8 JSON such as
//! `[{"file":"resources\app.asar","alg":"SHA256","value":"<64 hex>"}]`, where
//! the value is the SHA256 of the archive's *length-prefixed pickle header
//! blob* — not of the whole file. Electron itself never reads it (its runtime
//! check is already disabled by [`crate::fuse`]), but `WandAuxiliaryService.exe`
//! re-validates `app.asar` against this resource on 12.61+ and refuses to
//! cooperate on a mismatch, so repacking the archive leaves the value stale.
//!
//! Builds before 12.61 carry no such resource; that is reported as
//! [`IntegrityOutcome::NotFound`] and skipped rather than treated as failure.

use crate::error::{Result, YouModError};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Raw UTF-8 prefix of the resource's JSON, matched verbatim. The separator in
/// `resources\app.asar` is JSON-escaped, hence the doubled backslash.
const ANCHOR_PREFIX: &[u8] = br#""file":"resources\\app.asar","alg":"SHA256","value":""#;

/// Length of the lowercase SHA256 hex digest the resource stores.
const HASH_HEX_LEN: usize = 64;

/// Read window used by the streaming anchor search.
const CHUNK_SIZE: usize = 1 << 20;

/// Upper bound Electron/Wand accept for the asar header blob (64 MiB).
const MAX_HEADER_SIZE: u32 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityOutcome {
    /// The baked hash was stale and has been rewritten in place.
    Patched,
    /// The baked hash already matched; the exe was left untouched.
    AlreadyCorrect,
    /// No `ElectronAsar\Integrity` resource in this build (pre-12.61); skipped.
    NotFound,
}

/// SHA256 (lowercase hex) of the archive's header blob, using the same layout
/// Wand's own `AsarHeaderHash` reads: a 16-byte pickle prefix followed by the
/// header JSON it describes.
pub fn compute_asar_header_hash(asar_path: &Path) -> Result<String> {
    let mut file = File::open(asar_path).map_err(|e| io_err(asar_path, e))?;
    let file_len = file.metadata().map_err(|e| io_err(asar_path, e))?.len();

    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix)
        .map_err(|e| io_err(asar_path, e))?;

    let sentinel = u32::from_le_bytes(prefix[0..4].try_into().unwrap());
    let payload_size = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
    let string_field_size = u32::from_le_bytes(prefix[8..12].try_into().unwrap());
    let header_length = u32::from_le_bytes(prefix[12..16].try_into().unwrap());

    // Order matters: `payload_size >= 8` must hold before the subtractions.
    if sentinel != 4
        || payload_size < 8
        || string_field_size != payload_size - 4
        || header_length > string_field_size - 4
        || header_length > MAX_HEADER_SIZE
        || 16 + u64::from(header_length) > file_len
    {
        return Err(YouModError::Other(anyhow::anyhow!(
            "{} 的 ASAR 头部无效",
            asar_path.display()
        )));
    }

    let mut header = vec![0u8; header_length as usize];
    file.read_exact(&mut header)
        .map_err(|e| io_err(asar_path, e))?;

    Ok(to_hex(&Sha256::digest(&header)))
}

/// Rewrites the resource's 64 hex characters in place so it matches `asar_path`.
///
/// Same length in and out, so the resource and the rest of the PE never move.
pub fn patch_integrity_resource(exe_path: &Path, asar_path: &Path) -> Result<IntegrityOutcome> {
    let new_hash = compute_asar_header_hash(asar_path)?;
    if new_hash.len() != HASH_HEX_LEN {
        return Err(YouModError::Other(anyhow::anyhow!(
            "计算所得的 ASAR 头部 hash 不是 64 位十六进制，无法安全改写完整性资源"
        )));
    }

    let Some(hash_offset) = find_sole_hash_offset(exe_path)? else {
        return Ok(IntegrityOutcome::NotFound);
    };

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(exe_path)
        .map_err(|e| io_err(exe_path, e))?;

    let mut existing = [0u8; HASH_HEX_LEN];
    file.seek(SeekFrom::Start(hash_offset))
        .map_err(|e| io_err(exe_path, e))?;
    file.read_exact(&mut existing)
        .map_err(|e| io_err(exe_path, e))?;

    if !is_lowercase_hex(&existing) {
        return Err(YouModError::Other(anyhow::anyhow!(
            "ASAR 完整性资源的值不是 64 位小写十六进制，资源格式可能已变化"
        )));
    }

    if existing[..] == new_hash.as_bytes()[..] {
        return Ok(IntegrityOutcome::AlreadyCorrect);
    }

    file.seek(SeekFrom::Start(hash_offset))
        .map_err(|e| io_err(exe_path, e))?;
    file.write_all(new_hash.as_bytes())
        .map_err(|e| io_err(exe_path, e))?;

    Ok(IntegrityOutcome::Patched)
}

/// File offset of the digest immediately following the sole anchor match.
///
/// `None` when the anchor is absent (the resource does not exist in this
/// build); an error when it appears more than once, since the real one is then
/// ambiguous.
fn find_sole_hash_offset(exe_path: &Path) -> Result<Option<u64>> {
    let mut file = File::open(exe_path).map_err(|e| io_err(exe_path, e))?;

    // Keep just enough tail bytes that a match straddling two reads is not missed.
    let overlap = ANCHOR_PREFIX.len() + HASH_HEX_LEN - 1;
    let mut buffer = vec![0u8; CHUNK_SIZE + ANCHOR_PREFIX.len() + HASH_HEX_LEN];
    let mut buffer_start: u64 = 0;
    let mut filled: usize = 0;
    let mut found: Option<u64> = None;

    loop {
        filled += read_some(&mut file, &mut buffer[filled..]).map_err(|e| io_err(exe_path, e))?;

        // Only look where the anchor *and* the 64 bytes it guards are buffered.
        if filled >= ANCHOR_PREFIX.len() + HASH_HEX_LEN {
            let last = filled - ANCHOR_PREFIX.len() - HASH_HEX_LEN;
            for i in 0..=last {
                if buffer[i..].starts_with(ANCHOR_PREFIX) {
                    if found.is_some() {
                        return Err(YouModError::Other(anyhow::anyhow!(
                            "{} 中存在多处 ASAR 完整性资源匹配，无法确定真正的那个",
                            exe_path.display()
                        )));
                    }
                    found = Some(buffer_start + (i + ANCHOR_PREFIX.len()) as u64);
                }
            }
        }

        if filled < buffer.len() {
            break;
        }

        buffer.copy_within(filled - overlap..filled, 0);
        buffer_start += (filled - overlap) as u64;
        filled = overlap;
    }

    Ok(found)
}

fn read_some(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn is_lowercase_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn io_err(path: &Path, source: std::io::Error) -> YouModError {
    YouModError::Io {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// A genuine archive written by the same `asar-rust` used in production.
    fn make_real_asar(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("index.js"), b"console.log('hi');").unwrap();
        let asar = dir.join("app.asar");
        asar_rust::create_package(&src, &asar).unwrap();
        asar
    }

    fn fake_exe_with(dir: &Path, hash: &str, second: Option<&str>) -> PathBuf {
        let mut body = Vec::new();
        body.extend_from_slice(b"JUNKJUNK");
        body.extend_from_slice(ANCHOR_PREFIX);
        body.extend_from_slice(hash.as_bytes());
        if let Some(other) = second {
            body.extend_from_slice(b"MIDDLE");
            body.extend_from_slice(ANCHOR_PREFIX);
            body.extend_from_slice(other.as_bytes());
        }
        body.extend_from_slice(b"TAIL");
        let exe = dir.join("Wand.exe");
        fs::write(&exe, &body).unwrap();
        exe
    }

    #[test]
    fn compute_hash_matches_asar_header_blob() {
        let tmp = TempDir::new().unwrap();
        let asar = make_real_asar(tmp.path());

        let bytes = fs::read(&asar).unwrap();
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 4);
        let header_length = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let expected = to_hex(&Sha256::digest(&bytes[16..16 + header_length]));

        let computed = compute_asar_header_hash(&asar).unwrap();
        assert_eq!(computed, expected);
        assert_eq!(computed.len(), HASH_HEX_LEN);
        assert!(is_lowercase_hex(computed.as_bytes()));
    }

    #[test]
    fn compute_hash_rejects_invalid_header() {
        let tmp = TempDir::new().unwrap();
        let bogus = tmp.path().join("bogus.asar");
        fs::write(&bogus, b"not an asar at all, really").unwrap();
        assert!(compute_asar_header_hash(&bogus).is_err());
    }

    #[test]
    fn patch_rewrites_hash_in_place() {
        let tmp = TempDir::new().unwrap();
        let asar = make_real_asar(tmp.path());
        let stale = "0".repeat(HASH_HEX_LEN);
        let exe = fake_exe_with(tmp.path(), &stale, None);
        let len_before = fs::metadata(&exe).unwrap().len();

        assert_eq!(
            patch_integrity_resource(&exe, &asar).unwrap(),
            IntegrityOutcome::Patched
        );

        let bytes = fs::read(&exe).unwrap();
        assert_eq!(bytes.len() as u64, len_before, "the file must not move");
        let offset = b"JUNKJUNK".len() + ANCHOR_PREFIX.len();
        assert_eq!(
            &bytes[offset..offset + HASH_HEX_LEN],
            compute_asar_header_hash(&asar).unwrap().as_bytes()
        );
        assert!(bytes.ends_with(b"TAIL"));

        assert_eq!(
            patch_integrity_resource(&exe, &asar).unwrap(),
            IntegrityOutcome::AlreadyCorrect
        );
    }

    #[test]
    fn patch_skips_when_anchor_absent() {
        let tmp = TempDir::new().unwrap();
        let asar = make_real_asar(tmp.path());
        let exe = tmp.path().join("Wand.exe");
        fs::write(&exe, b"a build with no integrity resource").unwrap();

        assert_eq!(
            patch_integrity_resource(&exe, &asar).unwrap(),
            IntegrityOutcome::NotFound
        );
    }

    #[test]
    fn patch_rejects_ambiguous_anchor() {
        let tmp = TempDir::new().unwrap();
        let asar = make_real_asar(tmp.path());
        let dupe = "0".repeat(HASH_HEX_LEN);
        let exe = fake_exe_with(tmp.path(), &dupe, Some(&dupe));

        assert!(patch_integrity_resource(&exe, &asar).is_err());
    }

    #[test]
    fn patch_rejects_non_hex_value() {
        let tmp = TempDir::new().unwrap();
        let asar = make_real_asar(tmp.path());
        let exe = fake_exe_with(tmp.path(), &"z".repeat(HASH_HEX_LEN), None);

        assert!(patch_integrity_resource(&exe, &asar).is_err());
    }
}
