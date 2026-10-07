//! Applies [`crate::patches::JsPatch`] entries to the extracted `app.asar`.

use crate::error::{Result, YouModError};
use crate::js_edit::{self, JsEdit, Located};
use crate::patches::{JsPatch, PatchOp};
use oxc_allocator::Allocator;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct PatchResult {
    pub applied: Vec<String>,
    pub failed: Vec<String>,
}

pub fn patch_js_files(unpacked_dir: &Path, patches: &[&JsPatch]) -> Result<PatchResult> {
    let mut applied_indices: HashSet<usize> = HashSet::new();

    let js_files = find_candidate_js_files(unpacked_dir)?;

    // Phase 1: collect all modifications in memory — do NOT write to disk yet.
    // If any patch fails with an error, we bail out without touching any file.
    struct FileMod {
        path: PathBuf,
        content: String,
    }
    let mut modifications: Vec<FileMod> = Vec::new();

    for js_path in &js_files {
        let file_name = js_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let mut content = fs::read_to_string(js_path).map_err(|e| YouModError::Io {
            path: js_path.display().to_string(),
            source: e,
        })?;
        let original_content = content.clone();

        let candidates: Vec<usize> = patches
            .iter()
            .enumerate()
            .filter(|(_, patch)| should_apply_to_file(patch, file_name))
            .filter(|(_, patch)| contains_search_hint(&content, patch.search_hints))
            .map(|(index, _)| index)
            .collect();
        if candidates.is_empty() {
            continue;
        }

        let mut edits: Vec<JsEdit> = Vec::new();

        // Every structural patch keys off the same parse of this bundle.
        // The borrow of `content` ends with this block so the splices below
        // can replace it.
        {
            let allocator = Allocator::default();
            let program = js_edit::parse(&allocator, &content);

            for &index in &candidates {
                let patch = patches[index];
                let marker = patch.payload_marker.unwrap_or("");

                let located = match &patch.op {
                    PatchOp::WrapReturn { method, wrapper } => match &program {
                        Some(program) => {
                            js_edit::wrap_return(program, &content, method, wrapper, marker)
                        }
                        None => continue,
                    },
                    PatchOp::ReplaceBody { method, body } => match &program {
                        Some(program) => {
                            js_edit::replace_body(program, &content, method, body, marker)
                        }
                        None => continue,
                    },
                    PatchOp::WrapReducerAccount { anchor, template } => match &program {
                        Some(program) => js_edit::wrap_reducer_account(
                            program, &content, anchor, template, marker,
                        ),
                        None => continue,
                    },
                    PatchOp::ReplaceText {
                        target,
                        replacement,
                        single_match,
                    } => {
                        // The replacement no longer matches `target`, so a
                        // second run has to recognise it by hand.
                        if !marker.is_empty() && content.contains(marker) {
                            Located::AlreadyPatched
                        } else {
                            let Some(matched) = target.find(&content) else {
                                continue;
                            };
                            if *single_match {
                                let count = target.find_iter(&content).count();
                                if count > 1 {
                                    return Err(YouModError::PatchMultipleMatches {
                                        name: patch.name.to_string(),
                                        count,
                                    });
                                }
                            }
                            Located::Edits(vec![JsEdit {
                                start: matched.start(),
                                end: matched.end(),
                                text: replacement.to_string(),
                            }])
                        }
                    }
                };

                match located {
                    Located::Edits(splices) => {
                        edits.extend(splices);
                        applied_indices.insert(index);
                    }
                    Located::AlreadyPatched => {
                        applied_indices.insert(index);
                    }
                    Located::Absent => {}
                }
            }
        }

        if !edits.is_empty() {
            content = js_edit::apply_edits(&content, edits);
        }

        if content != original_content {
            modifications.push(FileMod {
                path: js_path.clone(),
                content,
            });
        }
    }

    // Phase 2: all patches validated — write files atomically
    for fm in &modifications {
        let tmp_path = fm.path.with_extension(".js.youmod-tmp");
        fs::write(&tmp_path, &fm.content).map_err(|e| YouModError::Io {
            path: tmp_path.display().to_string(),
            source: e,
        })?;
        fs::rename(&tmp_path, &fm.path).map_err(|e| YouModError::Io {
            path: fm.path.display().to_string(),
            source: e,
        })?;
    }

    let mut applied = Vec::new();
    let mut failed = Vec::new();
    for (index, patch) in patches.iter().enumerate() {
        if applied_indices.contains(&index) {
            applied.push(patch.name.to_string());
        } else {
            failed.push(patch.name.to_string());
        }
    }

    Ok(PatchResult { applied, failed })
}

fn should_apply_to_file(patch: &JsPatch, file_name: &str) -> bool {
    if patch.candidate_files.is_empty() {
        return true;
    }
    patch.candidate_files.contains(&file_name)
}

fn contains_search_hint(content: &str, hints: &[&str]) -> bool {
    if hints.is_empty() {
        return true;
    }
    hints.iter().any(|hint| content.contains(hint))
}

/// Bundles are the renderer chunks Wand loads by name plus the main process
/// entry point; all of them sit at the archive root.
fn find_candidate_js_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| YouModError::Io {
        path: dir.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| YouModError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        if path.is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && name.ends_with(".js")
        {
            files.push(path);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patches::PATCHES;
    use std::fs;
    use tempfile::TempDir;

    fn all_patches() -> Vec<&'static JsPatch> {
        PATCHES.iter().collect()
    }

    fn create_test_js_file(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(name), content).unwrap();
    }

    /// Mirrors the shape of Wand 12.61's `app-*.bundle.js` account API class.
    const ACCOUNT_BUNDLE: &str = concat!(
        "class X{",
        r#"requestRemoteAuthCode(){return this.#e.post("/v3/auth/remote_code")}"#,
        r#"getUserAccount(){return this.#e.fetch({endpoint:"/v3/account",method:"GET",name:"/v3/account",collectMetrics:!1})}"#,
        r#"setAccountLanguage(e,t){return this.#e.post("/v3/account/language",{tag:e,auto:t})}"#,
        r#"setAccountWandBrandExperience(){return this.#e.post("/v3/account/brand_experience_wand")}"#,
        "}",
    );

    /// Mirrors the shape of Wand 12.61's `app-*.bundle.js` account reducer.
    const REDUCER_BUNDLE: &str =
        r#"const m="ACTION_SET_ACCOUNT";function p(t,e){return{...t,account:e}}"#;

    const UPDATE_BUNDLE: &str = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{let t=e.updateInfo.url}))))"#;

    #[test]
    fn applies_every_patch_to_mock_bundles() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(unpacked, "index.js", UPDATE_BUNDLE);
        create_test_js_file(unpacked, "app-1234.bundle.js", ACCOUNT_BUNDLE);
        create_test_js_file(unpacked, "overlay-5678.bundle.js", REDUCER_BUNDLE);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();

        assert_eq!(result.failed, Vec::<String>::new());
        assert_eq!(result.applied.len(), 6);

        let bundle = fs::read_to_string(unpacked.join("app-1234.bundle.js")).unwrap();
        assert!(bundle.contains(concat!(
            r#"getUserAccount(){return (this.#e.fetch({endpoint:"/v3/account",method:"GET","#,
            r#"name:"/v3/account",collectMetrics:!1})).then((response)=>"#,
        )));
        assert!(bundle.contains(r#"setAccountLanguage(e,t){return (this.#e.post("#));
        assert!(bundle.contains(concat!(
            "requestRemoteAuthCode(){return Promise.reject(",
            "new Error(\"you-mod: native mobile pairing disabled\"))}"
        )));
        assert!(!bundle.contains("/v3/auth/remote_code"));

        let reducer = fs::read_to_string(unpacked.join("overlay-5678.bundle.js")).unwrap();
        assert!(reducer.contains("account:((account)=>"));

        let index = fs::read_to_string(unpacked.join("index.js")).unwrap();
        assert!(index.contains("e=>null"));
    }

    #[test]
    fn patches_every_copy_of_a_bundle() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(unpacked, "app-1234.bundle.js", ACCOUNT_BUNDLE);
        create_test_js_file(unpacked, "overlay-1234.bundle.js", ACCOUNT_BUNDLE);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert!(result.applied.iter().any(|n| n.contains("getUserAccount")));

        for name in ["app-1234.bundle.js", "overlay-1234.bundle.js"] {
            let content = fs::read_to_string(unpacked.join(name)).unwrap();
            assert!(
                content.contains("(this.#e.fetch("),
                "{name} was not patched"
            );
        }
    }

    #[test]
    fn running_twice_changes_nothing_further() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(unpacked, "index.js", UPDATE_BUNDLE);
        create_test_js_file(unpacked, "app-1234.bundle.js", ACCOUNT_BUNDLE);
        create_test_js_file(unpacked, "overlay-5678.bundle.js", REDUCER_BUNDLE);

        patch_js_files(unpacked, &all_patches()).unwrap();
        let once: Vec<String> = ["index.js", "app-1234.bundle.js", "overlay-5678.bundle.js"]
            .iter()
            .map(|name| fs::read_to_string(unpacked.join(name)).unwrap())
            .collect();

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert_eq!(
            result.failed,
            Vec::<String>::new(),
            "second run must report success"
        );

        for (name, before) in ["index.js", "app-1234.bundle.js", "overlay-5678.bundle.js"]
            .iter()
            .zip(once)
        {
            assert_eq!(
                fs::read_to_string(unpacked.join(name)).unwrap(),
                before,
                "{name} changed on the second run"
            );
        }
    }

    #[test]
    fn no_match_returns_failed() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(unpacked, "app-test.bundle.js", "console.log('hello');");

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert_eq!(result.applied.len(), 0);
        assert_eq!(result.failed.len(), 6);
    }

    #[test]
    fn unparseable_bundle_fails_loudly_instead_of_half_patching() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        // Contains the hint but is not valid JavaScript.
        create_test_js_file(
            unpacked,
            "app-broken.bundle.js",
            r#"getUserAccount( { return this.#x.fetch("#,
        );

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert!(result.failed.iter().any(|n| n.contains("getUserAccount")));
    }

    #[test]
    fn candidate_file_filter() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(unpacked, "other.bundle.js", UPDATE_BUNDLE);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert!(result.failed.iter().any(|n| n.contains("Disable Updates")));
    }

    #[test]
    fn structural_patches_ignore_call_sites() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(
            unpacked,
            "app-1234.bundle.js",
            "const a = api.getUserAccount();const b = api.setAccountLanguage('en');",
        );

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert!(!result.applied.iter().any(|n| n.contains("getUserAccount")));
        assert!(
            !result
                .applied
                .iter()
                .any(|n| n.contains("setAccountLanguage"))
        );
    }

    #[test]
    fn empty_js_file_is_skipped() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        create_test_js_file(unpacked, "empty.bundle.js", "");

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert_eq!(result.applied.len(), 0);
    }
}
