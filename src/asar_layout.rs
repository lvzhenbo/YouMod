//! Reproduces an archive's own packed/unpacked split when it is rebuilt.
//!
//! Wand keeps roughly 116 MB of native modules — the auxiliary service, the
//! OBS capture stack, the overlay renderers — in the sibling
//! `app.asar.unpacked` directory and only the rest inside `app.asar`.
//! `asar-rust` decides that split from a single glob, and its patterns are
//! globs rather than regexes (`^`, `.` and `$` are literal characters, `[...]`
//! is a character class, and there is no escape syntax), so the rule is read
//! back out of the archive being replaced instead of hardcoded: a future build
//! that moves those files would otherwise silently get them inlined, tripling
//! the archive.

use crate::error::{Result, YouModError};
use asar_rust as asar;
use asar_rust::disk::AsarError;
use asar_rust::filesystem::FilesystemEntry;
use std::fs;
use std::path::{Path, PathBuf};

/// Glob fragment matching either path separator. `asar-rust` globs the
/// platform-native relative path, which is backslash-separated on Windows.
const SEPARATOR: &str = r"[/\\]";

/// How an archive splits its contents between itself and its `.unpacked`
/// directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackedLayout {
    /// Glob matching everything the archive stores beside itself.
    pub unpack: Option<String>,
    /// Glob matching the unpacked directories themselves, which carry a flag
    /// of their own in the archive header.
    pub unpack_dir: Option<String>,
}

impl PackedLayout {
    /// Stores everything inside the archive. The fallback when the existing
    /// archive describes no clean unpacked subtree.
    pub fn all_packed() -> Self {
        Self::default()
    }

    /// True when nothing is stored beside the archive.
    pub fn is_all_packed(&self) -> bool {
        self.unpack.is_none() && self.unpack_dir.is_none()
    }

    /// Reads the split back out of an existing archive.
    pub fn of(asar_path: &Path) -> Result<Self> {
        Ok(Self::from_split(&classify(asar_path)?))
    }

    /// Derives a single-subtree rule from the archive's own entry flags.
    ///
    /// Takes the deepest directory that contains every unpacked entry and no
    /// packed one, so the rule reproduces the archive as it is rather than as
    /// this build expects it to be. A split that is not a clean subtree —
    /// unpacked and packed files interleaved below the same directory — cannot
    /// be expressed by one glob, and falls back to packing everything.
    fn from_split(split: &Split) -> Self {
        let mut candidates: Vec<&str> = split
            .directories
            .iter()
            .filter(|dir| split.unpacked.iter().all(|path| contains(dir, path)))
            .filter(|dir| !split.packed.iter().any(|path| contains(dir, path)))
            .map(String::as_str)
            .collect();
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));

        match candidates.first() {
            Some(candidate) if !candidate.is_empty() => {
                let prefix = candidate.split('/').collect::<Vec<_>>().join(SEPARATOR);
                Self {
                    unpack: Some(format!("{prefix}{SEPARATOR}*")),
                    unpack_dir: Some(prefix),
                }
            }
            _ => Self::all_packed(),
        }
    }
}

/// Writes `unpacked_dir` back out as an archive, reproducing `layout`.
///
/// `asar-rust` materialises the unpacked half at `<dest>.unpacked`, and the
/// repack source *is* `<app.asar>.unpacked` — the same path — so building the
/// archive in place makes it copy every unpacked file onto itself. Windows
/// refuses that and the archive is left truncated, so the replacement is built
/// beside its destination and moved into place once it is complete.
pub fn write_archive(unpacked_dir: &Path, dest_asar: &Path, layout: &PackedLayout) -> Result<()> {
    let staging = staging_path(dest_asar);
    let staging_unpacked = unpacked_path(&staging);
    discard(&staging);
    discard(&staging_unpacked);

    let result = build_archive(unpacked_dir, &staging, layout)
        .and_then(|()| replace_archive(&staging, dest_asar));

    // `discard` also clears the copies `asar-rust` made of the unpacked half,
    // which are already in place beside the destination.
    discard(&staging);
    discard(&staging_unpacked);

    result
}

fn build_archive(unpacked_dir: &Path, staging: &Path, layout: &PackedLayout) -> Result<()> {
    let options = asar::CreateOptions {
        dot: false,
        ordering: None,
        unpack: layout.unpack.clone(),
        unpack_dir: layout.unpack_dir.clone(),
    };
    asar::create_package_with_options(unpacked_dir, staging, options).map_err(|e| {
        YouModError::AsarOp {
            op: "repack",
            source: e.into(),
        }
    })?;

    // The crawler accepts a missing source directory and hands back an empty
    // archive, which must never replace a working install.
    let entries = open(staging).and_then(|archive| list(&archive))?;
    if entries.is_empty() {
        return Err(YouModError::Other(anyhow::anyhow!(
            "repacking {} produced an empty archive",
            unpacked_dir.display()
        )));
    }

    Ok(())
}

fn replace_archive(staging: &Path, dest_asar: &Path) -> Result<()> {
    fs::rename(staging, dest_asar).map_err(|e| YouModError::Io {
        path: dest_asar.display().to_string(),
        source: e,
    })
}

/// Where a replacement archive is built, on the destination's volume so moving
/// it into place is an atomic rename.
fn staging_path(dest_asar: &Path) -> PathBuf {
    let name = dest_asar
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("app.asar");
    dest_asar.with_file_name(format!("{name}.youmod-staging"))
}

/// Where `asar-rust` puts the unpacked half of an archive at `archive`.
fn unpacked_path(archive: &Path) -> PathBuf {
    PathBuf::from(format!("{}.unpacked", archive.display()))
}

fn discard(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(path);
}

/// Deletes the copies an extraction left in `unpacked_dir` for entries the
/// archive now stores inside itself, leaving that directory holding exactly
/// what the header marks unpacked. Returns the number of files removed.
///
/// Directories are only removed once empty, so anything Wand shipped there
/// survives.
pub fn prune_extracted_copies(unpacked_dir: &Path, asar_path: &Path) -> Result<usize> {
    let archive = open(asar_path)?;
    let entries = list(&archive)?;

    let mut removed = 0;
    let mut emptied: Vec<PathBuf> = Vec::new();

    for entry in &entries {
        let relative = entry.trim_start_matches('/');
        let node = archive.stat(relative, false).map_err(asar_error)?;
        let target = unpacked_dir.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));

        let (stored_inside, empty_candidate) = match &node {
            FilesystemEntry::File(file) => (!file.unpacked, false),
            FilesystemEntry::Link(link) => (!link.unpacked, false),
            // Directories only matter once the extraction's files are gone.
            FilesystemEntry::Directory(dir) => (false, !dir.unpacked),
        };

        if empty_candidate {
            emptied.push(target);
            continue;
        }
        if !stored_inside {
            continue;
        }

        match fs::remove_file(&target) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(YouModError::Io {
                    path: target.display().to_string(),
                    source: e,
                });
            }
        }
    }

    // Deepest first, so a directory the extraction created can go once its
    // contents are gone.
    emptied.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in emptied {
        let _ = fs::remove_dir(&dir);
    }

    Ok(removed)
}

/// An archive's entries, split by where the archive stores them and which of
/// them are directories.
#[derive(Debug, Default)]
struct Split {
    unpacked: Vec<String>,
    packed: Vec<String>,
    directories: Vec<String>,
}

/// Splits an archive's entries into the ones it stores beside itself and the
/// ones it stores inside.
fn classify(asar_path: &Path) -> Result<Split> {
    let archive = open(asar_path)?;
    let entries = list(&archive)?;

    let mut split = Split::default();
    for entry in &entries {
        let relative = entry.trim_start_matches('/');
        let node = archive.stat(relative, false).map_err(asar_error)?;
        let stored_unpacked = match &node {
            FilesystemEntry::File(file) => file.unpacked,
            FilesystemEntry::Link(link) => link.unpacked,
            FilesystemEntry::Directory(dir) => {
                split.directories.push(relative.to_string());
                dir.unpacked
            }
        };

        if stored_unpacked {
            split.unpacked.push(relative.to_string());
        } else {
            split.packed.push(relative.to_string());
        }
    }

    Ok(split)
}

fn open(asar_path: &Path) -> Result<asar::AsarArchive> {
    asar::AsarArchive::open(asar_path).map_err(asar_error)
}

fn list(archive: &asar::AsarArchive) -> Result<Vec<String>> {
    archive.list().map_err(asar_error)
}

fn asar_error(error: AsarError) -> YouModError {
    YouModError::AsarOp {
        op: "layout",
        source: error.into(),
    }
}

/// True when `dir` is `path` itself or one of its ancestors.
fn contains(dir: &str, path: &str) -> bool {
    dir == path || is_under(path, dir)
}

/// True when `path` sits strictly below `prefix`.
fn is_under(path: &str, prefix: &str) -> bool {
    path.len() > prefix.len() && path.as_bytes()[prefix.len()] == b'/' && path.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn split(unpacked: &[&str], packed: &[&str], directories: &[&str]) -> Split {
        Split {
            unpacked: unpacked.iter().map(|path| path.to_string()).collect(),
            packed: packed.iter().map(|path| path.to_string()).collect(),
            directories: directories.iter().map(|path| path.to_string()).collect(),
        }
    }

    fn wands_split() -> Split {
        // Wand 12.61: 155 files and 23 directories under `static/unpacked`,
        // nothing unpacked anywhere else.
        split(
            &[
                "static/unpacked",
                "static/unpacked/auxiliary",
                "static/unpacked/auxiliary/WandAuxiliaryService.exe",
                "static/unpacked/capture/release/bin/64bit/graphics-hook64.dll",
            ],
            &["index.js", "static/other.txt", "staticly.js"],
            &[
                "static",
                "static/unpacked",
                "static/unpacked/auxiliary",
                "static/unpacked/capture/release/bin/64bit",
            ],
        )
    }

    #[test]
    fn derives_wands_static_unpacked_subtree() {
        let layout = PackedLayout::from_split(&wands_split());

        assert_eq!(layout.unpack.as_deref(), Some(r"static[/\\]unpacked[/\\]*"));
        assert_eq!(layout.unpack_dir.as_deref(), Some(r"static[/\\]unpacked"));
    }

    #[test]
    fn walks_up_to_a_directory_that_covers_every_unpacked_entry() {
        let layout = PackedLayout::from_split(&split(
            &["a/b/x.dll", "a/c/y.dll"],
            &["index.js"],
            &["a", "a/b", "a/c"],
        ));

        assert_eq!(layout.unpack.as_deref(), Some(r"a[/\\]*"));
        assert_eq!(layout.unpack_dir.as_deref(), Some("a"));
    }

    #[test]
    fn falls_back_when_unpacked_and_packed_files_interleave() {
        // `a/b/y.dll` is unpacked but its sibling `a/b/keep.txt` is packed; one
        // glob cannot express that, so everything goes back inside.
        let layout =
            PackedLayout::from_split(&split(&["a/b/x.dll"], &["a/b/keep.txt"], &["a", "a/b"]));

        assert_eq!(layout, PackedLayout::all_packed());
        assert!(PackedLayout::all_packed().is_all_packed());
    }

    #[test]
    fn no_unpacked_entries_means_everything_is_packed() {
        assert_eq!(
            PackedLayout::from_split(&split(&[], &["index.js"], &[])),
            PackedLayout::all_packed()
        );
    }

    #[test]
    fn a_single_unpacked_file_does_not_become_the_rule_itself() {
        // The rule must be the containing directory; matching the file path
        // would only ever mark that path, and as a directory at that.
        let layout = PackedLayout::from_split(&split(
            &["static/unpacked/a.dll"],
            &["index.js"],
            &["static", "static/unpacked"],
        ));

        assert_eq!(layout.unpack.as_deref(), Some(r"static[/\\]unpacked[/\\]*"));
        assert_eq!(layout.unpack_dir.as_deref(), Some(r"static[/\\]unpacked"));
    }

    #[test]
    fn a_fully_unpacked_archive_uses_a_top_level_rule() {
        let layout = PackedLayout::from_split(&split(&["bin/x.dll", "bin/y.dll"], &[], &["bin"]));

        assert_eq!(layout.unpack.as_deref(), Some(r"bin[/\\]*"));
    }

    #[test]
    fn a_root_level_directory_cannot_be_expressed() {
        let layout = PackedLayout::from_split(&split(&["x.dll"], &["index.js"], &[]));

        assert_eq!(layout, PackedLayout::all_packed());
    }

    #[test]
    fn contains_requires_a_separator_boundary() {
        assert!(contains("static/unpacked", "static/unpacked"));
        assert!(contains("static/unpacked", "static/unpacked/x.dll"));
        assert!(!contains("static/unpacked", "static/unpacked2/x.dll"));
        assert!(!contains("static/unpacked", "static/unpackedx"));
    }

    /// Builds an archive from `tree` and returns it, so the globs can be
    /// exercised through the same code path the orchestrator uses.
    fn pack(dir: &Path, dest: &Path, layout: &PackedLayout) {
        let options = asar::CreateOptions {
            dot: true,
            ordering: None,
            unpack: layout.unpack.clone(),
            unpack_dir: layout.unpack_dir.clone(),
        };
        asar::create_package_with_options(dir, dest, options).expect("pack");
    }

    fn wands_layout() -> PackedLayout {
        PackedLayout {
            unpack: Some(r"static[/\\]unpacked[/\\]*".into()),
            unpack_dir: Some(r"static[/\\]unpacked".into()),
        }
    }

    fn trees() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        for (relative, contents) in [
            ("index.js", "root"),
            ("static/other.txt", "other"),
            ("static/unpacked/top.dll", "top"),
            ("static/unpacked/auxiliary/deep.dll", "deep"),
        ] {
            let path = src.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        (tmp, src)
    }

    #[test]
    fn the_derived_globs_are_read_back_out_of_the_archive() {
        let (tmp, src) = trees();
        let asar_path = tmp.path().join("app.asar");
        pack(&src, &asar_path, &wands_layout());

        // The whole point: the rule is recovered from the archive itself.
        assert_eq!(PackedLayout::of(&asar_path).unwrap(), wands_layout());

        let split = classify(&asar_path).unwrap();

        assert!(
            split
                .unpacked
                .contains(&"static/unpacked/top.dll".to_string()),
            "a direct child must match, got {:?}",
            split.unpacked
        );
        assert!(
            split
                .unpacked
                .contains(&"static/unpacked/auxiliary/deep.dll".to_string()),
            "`*` must also span separators, got {:?}",
            split.unpacked
        );
        assert!(
            split.unpacked.contains(&"static/unpacked".to_string()),
            "the directory itself carries a flag, got {:?}",
            split.unpacked
        );
        assert!(
            split
                .directories
                .contains(&"static/unpacked/auxiliary".to_string())
        );
        assert!(!split.unpacked.contains(&"static/other.txt".to_string()));
        assert!(!split.unpacked.contains(&"index.js".to_string()));
        assert!(split.packed.contains(&"static/other.txt".to_string()));
    }

    #[test]
    fn a_repack_with_the_derived_rule_keeps_the_archive_the_same_size() {
        let (tmp, src) = trees();
        let first = tmp.path().join("first.asar");
        pack(&src, &first, &wands_layout());
        let first_size = fs::metadata(&first).unwrap().len();

        // The unpacked directory as Wand ships it: the unpacked subtree only.
        let work = tmp.path().join("work");
        for (relative, contents) in [
            ("static/unpacked/top.dll", "top"),
            ("static/unpacked/auxiliary/deep.dll", "deep"),
        ] {
            let path = work.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        // Exactly the orchestrator's order: extract, repack, then prune.
        asar::extract_all(&first, &work).unwrap();
        let derived = PackedLayout::of(&first).unwrap();
        assert_eq!(derived, wands_layout());

        let second = tmp.path().join("second.asar");
        pack(&work, &second, &derived);
        assert_eq!(
            fs::metadata(&second).unwrap().len(),
            first_size,
            "the repack must not pull the unpacked bytes back into the archive"
        );

        prune_extracted_copies(&work, &first).unwrap();
        assert!(
            !work.join("index.js").exists(),
            "prune left an inlined copy"
        );
        assert_eq!(
            fs::read_to_string(work.join("static/unpacked/top.dll")).unwrap(),
            "top",
            "prune removed an unpacked file"
        );
    }

    #[test]
    fn writing_in_place_does_not_copy_unpacked_files_onto_themselves() {
        // The repack source is `<app.asar>.unpacked`, which is exactly where
        // `asar-rust` materialises the unpacked half. Building the archive
        // directly there made it copy every unpacked file onto itself; Windows
        // refuses, leaving a truncated archive behind.
        let (tmp, src) = trees();
        let asar_path = tmp.path().join("app.asar");
        let work = unpacked_path(&asar_path);

        copy_tree(&src, &work);

        write_archive(&work, &asar_path, &wands_layout()).expect("repacking in place");

        let split = classify(&asar_path).unwrap();
        assert!(split.packed.contains(&"index.js".to_string()));
        assert!(
            split
                .unpacked
                .contains(&"static/unpacked/auxiliary/deep.dll".to_string())
        );
        assert_eq!(
            fs::read_to_string(work.join("static/unpacked/top.dll")).unwrap(),
            "top",
            "an unpacked file was damaged by the repack"
        );
        assert!(
            !staging_path(&asar_path).exists(),
            "the staging archive was left behind"
        );
        assert!(!unpacked_path(&staging_path(&asar_path)).exists());
    }

    #[test]
    fn a_failed_write_leaves_the_previous_archive_alone() {
        let (tmp, src) = trees();
        let asar_path = tmp.path().join("app.asar");
        pack(&src, &asar_path, &wands_layout());
        let good = fs::read(&asar_path).unwrap();

        // A source directory that does not exist cannot be packed.
        let missing = tmp.path().join("gone");
        assert!(write_archive(&missing, &asar_path, &wands_layout()).is_err());

        assert_eq!(
            fs::read(&asar_path).unwrap(),
            good,
            "the archive was clobbered"
        );
    }

    #[test]
    fn pruning_removes_the_extracted_copies_but_keeps_unpacked_files() {
        let (tmp, src) = trees();
        let asar_path = tmp.path().join("app.asar");
        pack(&src, &asar_path, &wands_layout());

        // What an extraction of that archive leaves behind.
        let work = tmp.path().join("work");
        asar::extract_all(&asar_path, &work).unwrap();
        assert!(work.join("index.js").exists());
        assert!(work.join("static/other.txt").exists());

        let removed = prune_extracted_copies(&work, &asar_path).unwrap();

        assert_eq!(removed, 2, "index.js and static/other.txt were inlined");
        assert!(!work.join("index.js").exists());
        assert!(!work.join("static/other.txt").exists());
        assert!(work.join("static/unpacked/top.dll").exists());
        assert!(work.join("static/unpacked/auxiliary/deep.dll").exists());
    }

    #[test]
    fn pruning_keeps_files_the_archive_does_not_know_about() {
        let (tmp, src) = trees();
        let asar_path = tmp.path().join("app.asar");
        pack(&src, &asar_path, &PackedLayout::all_packed());

        let work = tmp.path().join("work");
        asar::extract_all(&asar_path, &work).unwrap();
        fs::write(work.join("leftover.bin"), "wand's own").unwrap();

        prune_extracted_copies(&work, &asar_path).unwrap();

        assert!(work.join("leftover.bin").exists());
    }

    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap().filter_map(|entry| entry.ok()) {
            let dest = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &dest);
            } else {
                fs::copy(entry.path(), dest).unwrap();
            }
        }
    }

    fn count_files(dir: &Path) -> usize {
        let Ok(entries) = fs::read_dir(dir) else {
            return 0;
        };
        entries
            .filter_map(|entry| entry.ok())
            .map(|entry| {
                if entry.path().is_dir() {
                    count_files(&entry.path())
                } else {
                    1
                }
            })
            .sum()
    }

    /// Runs the whole rebuild against a real archive. Wand keeps 155 files —
    /// 116 MB of native modules and OBS binaries — outside `app.asar`, so a
    /// wrong rule inlines all of them and triples the archive.
    #[test]
    #[ignore = "needs a real Wand installation; set YOUMOD_WAND_ASAR"]
    fn a_real_archive_rebuilds_to_the_same_size() {
        let Some(source) = std::env::var_os("YOUMOD_WAND_ASAR").map(PathBuf::from) else {
            eprintln!("YOUMOD_WAND_ASAR is not set - nothing to validate");
            return;
        };
        assert!(source.is_file(), "not a file: {}", source.display());

        let tmp = TempDir::new().unwrap();
        // `asar-rust` looks for unpacked files in `<archive>.unpacked`, so the
        // working copy keeps Wand's naming.
        let asar = tmp.path().join("app.asar");
        let work = tmp.path().join("app.asar.unpacked");
        let repacked = tmp.path().join("repacked.asar");
        let original = classify(&source).unwrap();

        let layout = PackedLayout::of(&source).unwrap();
        println!(
            "derived rule: unpack={:?} unpack_dir={:?}",
            layout.unpack, layout.unpack_dir
        );
        assert_eq!(layout.unpack.as_deref(), Some(r"static[/\\]unpacked[/\\]*"));
        assert_eq!(layout.unpack_dir.as_deref(), Some(r"static[/\\]unpacked"));

        // Put back exactly the files the archive stores unpacked.
        let installed = source.parent().unwrap().join("app.asar.unpacked");
        for relative in &original.unpacked {
            let path = work.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            let file = installed.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            if file.is_file() {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::copy(&file, &path).unwrap();
            } else {
                fs::create_dir_all(&path).unwrap();
            }
        }
        let unpacked_files = count_files(&work);
        println!("unpacked files restored: {unpacked_files}");

        fs::copy(&source, &asar).unwrap();
        asar::extract_all(&asar, &work).unwrap();
        let extracted_files = count_files(&work);
        println!("files after extraction:   {extracted_files}");
        assert!(
            extracted_files > unpacked_files,
            "the extraction should have added the packed entries"
        );

        pack(&work, &repacked, &layout);
        prune_extracted_copies(&work, &repacked).unwrap();

        let original_size = fs::metadata(&source).unwrap().len();
        let repacked_size = fs::metadata(&repacked).unwrap().len();
        println!(
            "archive size: {:.1} MB -> {:.1} MB",
            original_size as f64 / 1048576.0,
            repacked_size as f64 / 1048576.0
        );
        assert!(
            repacked_size.abs_diff(original_size) < original_size / 100,
            "the rebuild changed the archive size by more than 1%"
        );

        let rebuilt = classify(&repacked).unwrap();
        assert_eq!(
            rebuilt.unpacked, original.unpacked,
            "the rebuild changed which entries live outside the archive"
        );
        assert_eq!(rebuilt.packed, original.packed);
        assert_eq!(
            count_files(&work),
            unpacked_files,
            "pruning left copies of the packed entries behind"
        );
    }
}
