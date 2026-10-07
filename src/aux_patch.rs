//! Neutralise the integrity gates Wand added to `WandAuxiliaryService.exe`.
//!
//! Ported from Wand-Enhancer's `AuxTrustNeutralizer` and
//! `AuxFuseIntegrityNeutralizer`. Wand 12.61 runs three independent checks
//! before dispatching *any* privileged auxiliary command, trainer DLL injection
//! included, and refuses with `client_integrity_failed` when one fails:
//!
//! 1. Authenticode trust — broken by the very act of patching `Wand.exe`, so
//!    every `WinVerifyTrust` caller is stubbed to report success.
//! 2. A re-check of the same Electron asar-integrity fuse [`crate::fuse`] clears
//!    so a patched `app.asar` loads; the service reads a disabled fuse as
//!    tampering, so the predicate is stubbed to always report it enabled.
//! 3. A comparison of `app.asar` against the hash baked into `Wand.exe` —
//!    handled by [`crate::asar_integrity`], not here.
//!
//! Both anchors are stable strings rather than Wand's per-build obfuscated
//! names, and both skip rather than fail when the feature is absent from an
//! older build. The managed image is read with `cildec`, so instruction
//! boundaries and signatures come from the ECMA-335 tables rather than
//! hand-rolled operand lengths.

use crate::error::{Result, YouModError};
use cildec::tables::{MethodDefRow, TypeDefRow};
use cildec::{
    InstructionIter, Metadata, MethodBody, MethodSig, OpCode, Operand, PeImage, TableId, Token,
    Type,
};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

/// Exact sentinel from `@electron/fuses` (`src/constants.ts`), shared with
/// [`crate::fuse`]. Stable across builds and unrelated to Wand's own naming.
const FUSE_SENTINEL: &str = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

/// Native import the auxiliary service uses to check trust.
const TRUST_IMPORT: &str = "WinVerifyTrust";

/// `ldc.i4.0; ret` — make a stubbed trust caller report `S_OK`.
const TRUST_STUB: [u8; 2] = [0x16, 0x2A];

/// `ldc.i4.1; ret` — make a stubbed predicate always report "fuse enabled".
const PREDICATE_STUB: [u8; 2] = [0x17, 0x2A];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxOutcome {
    /// This many methods were rewritten.
    Patched(usize),
    /// Every target was already stubbed; the file was left untouched.
    AlreadyPatched,
    /// The check does not exist in this build; nothing to do.
    Absent,
}

/// Stubs every method that calls `WinVerifyTrust` so it returns `S_OK`.
///
/// The stub replaces the first two IL bytes of the calling method, which makes
/// it report success immediately. Errors when the import or its callers cannot
/// be found: unlike the other gates this check has always been present, so its
/// absence means the auxiliary service is not one this tool knows how to treat.
pub fn neutralize_trust_check(aux_path: &Path) -> Result<AuxOutcome> {
    let bytes = read_image(aux_path)?;

    let Ok(image) = PeImage::parse(&bytes) else {
        return Err(YouModError::Other(anyhow::anyhow!(
            "{} 不是托管程序集，无法中和辅助服务信任校验",
            aux_path.display()
        )));
    };
    let metadata = image.metadata().map_err(|e| image_error(aux_path, e))?;

    let offsets = pinvoke_caller_il_offsets(aux_path, &image, &metadata, TRUST_IMPORT)?;
    if offsets.is_empty() {
        return Err(YouModError::Other(anyhow::anyhow!(
            "在 {} 中未找到 {} 调用方，辅助服务结构可能已变化",
            aux_path.display(),
            TRUST_IMPORT
        )));
    }

    Ok(report(write_stubs(aux_path, &offsets, TRUST_STUB)?))
}

/// Stubs the lone no-arg `bool` predicate on the type whose IL references the
/// Electron fuse sentinel, so the service sees the fuse as enabled.
///
/// Absent on builds before this check existed; that is reported, not failed.
pub fn neutralize_fuse_integrity_check(aux_path: &Path) -> Result<AuxOutcome> {
    let bytes = read_image(aux_path)?;

    let Ok(image) = PeImage::parse(&bytes) else {
        return Ok(AuxOutcome::Absent);
    };
    let Ok(metadata) = image.metadata() else {
        return Ok(AuxOutcome::Absent);
    };

    let Some(offset) = bool_predicate_il_offset(aux_path, &image, &metadata, FUSE_SENTINEL)? else {
        return Ok(AuxOutcome::Absent);
    };

    Ok(report(write_stubs(aux_path, &[offset], PREDICATE_STUB)?))
}

/// File offset of the first IL byte of every method that calls `import_name`.
///
/// `import_name` is the metadata name of the P/Invoke declaration (the C#
/// identifier); the runtime resolves the actual native export elsewhere.
fn pinvoke_caller_il_offsets(
    path: &Path,
    image: &PeImage<'_>,
    metadata: &Metadata<'_>,
    import_name: &str,
) -> Result<Vec<u64>> {
    let tables = metadata.tables();

    let mut target = None;
    for (rid, row) in tables.iter::<MethodDefRow>() {
        let row = row.map_err(|e| table_error(path, "MethodDef", e))?;
        if metadata.strings().str_opt(row.name) == Some(import_name) {
            target = Some(Token::new(TableId::MethodDef, rid));
            break;
        }
    }

    let Some(target) = target else {
        return Ok(Vec::new());
    };

    let mut offsets = Vec::new();
    for (_, row) in tables.iter::<MethodDefRow>() {
        let row = row.map_err(|e| table_error(path, "MethodDef", e))?;
        if row.has_no_body() {
            continue; // Abstract, P/Invoke, or otherwise bodyless.
        }

        let Ok(Some(body)) = MethodBody::from_image(image, &row) else {
            continue; // Malformed body: skip rather than trust a wrong offset.
        };

        if body_calls(body.instructions(), target) {
            offsets.push(il_file_offset(path, image, row.rva)?);
        }
    }

    Ok(offsets)
}

/// File offset of the first IL byte of the sole no-arg `bool` predicate on the
/// type whose IL references `anchor`.
///
/// `None` when no type references the anchor. An error when the anchor is
/// present but that type does not carry exactly one such method, since the
/// match would then be ambiguous.
fn bool_predicate_il_offset(
    path: &Path,
    image: &PeImage<'_>,
    metadata: &Metadata<'_>,
    anchor: &str,
) -> Result<Option<u64>> {
    let tables = metadata.tables();
    let anchor_units: Vec<u16> = anchor.encode_utf16().collect();
    let type_count = tables.row_count(TableId::TypeDef);

    for (type_rid, row) in tables.iter::<TypeDefRow>() {
        let row = row.map_err(|e| table_error(path, "TypeDef", e))?;

        // A type owns the methods from its `MethodList` up to the next type's.
        let start = row.method_list.token().rid().max(1);
        let end = if type_rid < type_count {
            tables
                .row::<TypeDefRow>(type_rid + 1)
                .map_err(|e| table_error(path, "TypeDef", e))?
                .method_list
                .token()
                .rid()
        } else {
            tables.row_count(TableId::MethodDef) + 1
        };

        let mut references_anchor = false;
        let mut predicate = None;
        let mut ambiguous = false;

        for rid in method_range(start, end) {
            let method = tables
                .row::<MethodDefRow>(rid)
                .map_err(|e| table_error(path, "MethodDef", e))?;
            if method.has_no_body() {
                continue;
            }

            let Ok(Some(body)) = MethodBody::from_image(image, &method) else {
                continue;
            };

            if !references_anchor && body_loads_user_string(metadata, &body, &anchor_units) {
                references_anchor = true;
            }

            if is_no_arg_boolean(metadata, &method) {
                if predicate.is_some() {
                    ambiguous = true;
                } else {
                    predicate = Some(method.rva);
                }
            }
        }

        if !references_anchor {
            continue;
        }

        if ambiguous {
            return Err(YouModError::Other(anyhow::anyhow!(
                "{}：锚定类型上有多个无参 bool 方法，无法确定完整性谓词",
                path.display()
            )));
        }

        return match predicate {
            Some(rva) => Ok(Some(il_file_offset(path, image, rva)?)),
            None => Err(YouModError::Other(anyhow::anyhow!(
                "{}：锚定类型上没有任何无参 bool 方法，无法定位完整性谓词",
                path.display()
            ))),
        };
    }

    Ok(None)
}

fn method_range(start: u32, end: u32) -> Range<u32> {
    start..end.max(start)
}

/// Whether the method body calls the method named by `target`.
fn body_calls(instructions: InstructionIter<'_>, target: Token) -> bool {
    for instruction in instructions {
        let Ok(instruction) = instruction else {
            return false;
        };

        if matches!(&instruction.opcode, OpCode::Call | OpCode::Callvirt)
            && matches!(&instruction.operand, Operand::Method(token) if *token == target)
        {
            return true;
        }
    }
    false
}

/// Whether the method body loads `anchor` with `ldstr`.
fn body_loads_user_string(metadata: &Metadata<'_>, body: &MethodBody<'_>, anchor: &[u16]) -> bool {
    for instruction in body.instructions() {
        let Ok(instruction) = instruction else {
            return false;
        };

        if let Operand::String(token) = &instruction.operand
            && let Ok(text) = metadata.user_strings().get(*token)
            && text.code_units().eq(anchor.iter().copied())
        {
            return true;
        }
    }
    false
}

/// Whether the method takes no arguments and returns a non-`byref` `bool`.
fn is_no_arg_boolean(metadata: &Metadata<'_>, method: &MethodDefRow) -> bool {
    let Ok(blob) = metadata.blobs().get(method.signature) else {
        return false;
    };
    let Ok(signature) = MethodSig::parse(blob) else {
        return false;
    };

    signature.param_count() == 0
        && !signature.return_type.by_ref
        && matches!(&signature.return_type.type_, Type::Boolean)
}

/// File offset of a method body's first IL byte, from its RVA.
fn il_file_offset(path: &Path, image: &PeImage<'_>, rva: u32) -> Result<u64> {
    let header = image.rva_to_offset(rva).ok_or_else(|| {
        YouModError::Other(anyhow::anyhow!(
            "{}：方法体 RVA {rva:#x} 不在任何节内",
            path.display()
        ))
    })?;

    let first = image
        .bytes()
        .get(header)
        .ok_or_else(|| YouModError::Other(anyhow::anyhow!("{}：方法体头越界", path.display())))?;

    // The IL follows the body header: 12 bytes when fat, 1 when tiny.
    let header_size = if first & 0x3 == 0x3 { 12 } else { 1 };
    Ok((header + header_size) as u64)
}

fn report(changed: usize) -> AuxOutcome {
    if changed == 0 {
        AuxOutcome::AlreadyPatched
    } else {
        AuxOutcome::Patched(changed)
    }
}

/// Writes `stub` at each offset, skipping the ones already carrying it.
///
/// Returns how many were actually rewritten, so re-patching is a no-op.
fn write_stubs(aux_path: &Path, offsets: &[u64], stub: [u8; 2]) -> Result<usize> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(aux_path)
        .map_err(|e| io_err(aux_path, e))?;

    let length = file.metadata().map_err(|e| io_err(aux_path, e))?.len();
    let mut changed = 0;

    for &offset in offsets {
        if offset + stub.len() as u64 > length {
            return Err(YouModError::Other(anyhow::anyhow!(
                "{} 中的 IL 偏移 {offset} 超出文件范围",
                aux_path.display()
            )));
        }

        let mut existing = [0u8; 2];
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| io_err(aux_path, e))?;
        file.read_exact(&mut existing)
            .map_err(|e| io_err(aux_path, e))?;
        if existing == stub {
            continue;
        }

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| io_err(aux_path, e))?;
        file.write_all(&stub).map_err(|e| io_err(aux_path, e))?;
        changed += 1;
    }

    file.flush().map_err(|e| io_err(aux_path, e))?;
    Ok(changed)
}

fn read_image(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| io_err(path, e))
}

fn io_err(path: &Path, source: std::io::Error) -> YouModError {
    YouModError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn image_error(path: &Path, error: cildec::Error) -> YouModError {
    YouModError::Other(anyhow::anyhow!(
        "{} 的托管元数据无法解码（{error}）",
        path.display()
    ))
}

fn table_error(path: &Path, table: &str, error: cildec::Error) -> YouModError {
    YouModError::Other(anyhow::anyhow!(
        "{} 的 {table} 表无法解码（{error}）",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn non_managed_file_is_reported_rather_than_patched() {
        let tmp = TempDir::new().unwrap();
        let fake = tmp.path().join("WandAuxiliaryService.exe");
        fs::write(&fake, b"this is definitely not a managed image").unwrap();

        assert!(neutralize_trust_check(&fake).is_err());
        // The fuse re-check has no anchor here, so it is simply absent.
        assert_eq!(
            neutralize_fuse_integrity_check(&fake).unwrap(),
            AuxOutcome::Absent
        );
    }

    #[test]
    fn existing_stub_bytes_are_recognised_as_already_patched() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("stub.bin");
        fs::write(&file, [TRUST_STUB, PREDICATE_STUB].concat()).unwrap();

        assert_eq!(write_stubs(&file, &[0], TRUST_STUB).unwrap(), 0);
        assert_eq!(write_stubs(&file, &[2], PREDICATE_STUB).unwrap(), 0);
        assert_eq!(write_stubs(&file, &[0], PREDICATE_STUB).unwrap(), 1);
        assert_eq!(
            fs::read(&file).unwrap(),
            [PREDICATE_STUB, PREDICATE_STUB].concat()
        );
    }

    #[test]
    fn writing_past_the_end_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("short.bin");
        fs::write(&file, [0u8; 2]).unwrap();

        assert!(write_stubs(&file, &[1], PREDICATE_STUB).is_err());
    }

    /// Exercises the table and heap readers against a managed image that ships
    /// with the machine, so the pipeline has coverage without a Wand install.
    /// Skipped when no such assembly is present.
    #[test]
    fn reads_a_real_managed_image() {
        let Some(path) = framework_assembly() else {
            return;
        };

        let bytes = fs::read(&path).unwrap();
        let image = PeImage::parse(&bytes).expect("a framework assembly is a managed PE");
        let metadata = image.metadata().expect("its metadata is readable");

        assert!(metadata.tables().row_count(TableId::TypeDef) > 0);
        assert!(metadata.tables().row_count(TableId::MethodDef) > 0);

        let first_name = (1..=metadata.tables().row_count(TableId::MethodDef))
            .find_map(|rid| metadata.tables().row::<MethodDefRow>(rid).ok())
            .and_then(|row| metadata.strings().str_opt(row.name))
            .map(str::to_owned);
        assert!(first_name.is_some_and(|name| !name.is_empty()));

        // The framework references no fuse sentinel, so nothing is stubbed.
        assert_eq!(
            neutralize_fuse_integrity_check(&path).unwrap(),
            AuxOutcome::Absent
        );
    }

    fn framework_assembly() -> Option<PathBuf> {
        [
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Core.dll",
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Core.dll",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    }

    /// Full-pipeline check against a real Wand installation.
    ///
    /// Ignored by default because CI has no Wand install; point
    /// `YOUMOD_WAND_AUX` at the real `WandAuxiliaryService.exe` and run
    /// `cargo test -- --ignored`. A copy is patched, never the given file.
    #[test]
    #[ignore = "needs a real Wand auxiliary service; set YOUMOD_WAND_AUX"]
    fn real_auxiliary_service_anchors_are_found_and_stubbed() {
        let Ok(source) = std::env::var("YOUMOD_WAND_AUX") else {
            return;
        };
        let source = PathBuf::from(source);
        assert!(source.is_file(), "{} is not a file", source.display());

        let tmp = TempDir::new().unwrap();
        let copy = tmp.path().join("WandAuxiliaryService.exe");
        fs::copy(&source, &copy).unwrap();

        let before = fs::read(&copy).unwrap();

        let AuxOutcome::Patched(trust_calls) = neutralize_trust_check(&copy).unwrap() else {
            panic!("the trust check should have been neutralised");
        };
        assert!(trust_calls >= 1);
        println!("{TRUST_IMPORT} callers stubbed: {trust_calls}");

        let after_trust = fs::read(&copy).unwrap();
        assert_eq!(
            after_trust.len(),
            before.len(),
            "the file must not change size"
        );
        assert_eq!(
            stub_report(&before, &after_trust, TRUST_STUB),
            (2 * trust_calls, true),
            "the trust stub must land in {trust_calls} two-byte pairs"
        );

        assert_eq!(
            neutralize_fuse_integrity_check(&copy).unwrap(),
            AuxOutcome::Patched(1)
        );
        let after_fuse = fs::read(&copy).unwrap();
        assert_eq!(
            stub_report(&after_trust, &after_fuse, PREDICATE_STUB),
            (2, true),
            "the predicate stub must land in one two-byte pair"
        );

        // Re-running finds nothing left to do.
        assert_eq!(
            neutralize_trust_check(&copy).unwrap(),
            AuxOutcome::AlreadyPatched
        );
        assert_eq!(
            neutralize_fuse_integrity_check(&copy).unwrap(),
            AuxOutcome::AlreadyPatched
        );
    }

    /// How many bytes differ, and whether they form pairs equal to `stub`.
    fn stub_report(before: &[u8], after: &[u8], stub: [u8; 2]) -> (usize, bool) {
        let differing: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i])
            .collect();
        let well_formed = differing.chunks(2).all(|pair| {
            pair.len() == 2
                && pair[0] + 1 == pair[1]
                && after[pair[0]] == stub[0]
                && after[pair[1]] == stub[1]
        });
        (differing.len(), well_formed)
    }
}
