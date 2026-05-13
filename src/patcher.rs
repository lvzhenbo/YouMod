use crate::error::{Result, YouModError};
use crate::patches::JsPatch;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct PatchResult {
    pub applied: Vec<String>,
    pub failed: Vec<String>,
}

pub fn patch_js_files(
    unpacked_dir: &Path,
    patches: &[&JsPatch],
) -> Result<PatchResult> {
    let mut applied_indices: HashSet<usize> = HashSet::new();
    let mut applied_names: Vec<String> = Vec::new();
    let mut failed_names: Vec<String> = Vec::new();

    let js_files = find_candidate_js_files(unpacked_dir)?;

    // Phase 1: collect all modifications in memory — do NOT write to disk yet.
    // If any patch fails with an error, we bail out without touching any file.
    struct FileMod {
        path: PathBuf,
        content: String,
    }
    let mut modifications: Vec<FileMod> = Vec::new();

    for js_path in &js_files {
        let file_name = js_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let mut content = fs::read_to_string(js_path).map_err(|e| YouModError::Io {
            path: js_path.display().to_string(),
            source: e,
        })?;
        let original_content = content.clone();

        for (i, patch) in patches.iter().enumerate() {
            if applied_indices.contains(&i) {
                continue;
            }

            if !should_apply_to_file(patch, file_name) {
                continue;
            }

            if !contains_search_hint(&content, patch.search_hints) {
                continue;
            }

            let re = &patch.target;
            let Some(matched) = re.find(&content) else {
                continue;
            };

            let matched_text = matched.as_str().to_string();

            if patch.single_match {
                let count = re.find_iter(&content).count();
                if count > 1 {
                    return Err(YouModError::PatchMultipleMatches {
                        name: patch.name.to_string(),
                        count,
                    });
                }
            }

            let replacement = build_replacement(patch, &matched_text)?;

            content = re.replace(&content, replacement.as_str()).to_string();
            applied_indices.insert(i);
            applied_names.push(patch.name.to_string());
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

    for (i, patch) in patches.iter().enumerate() {
        if !applied_indices.contains(&i) {
            failed_names.push(patch.name.to_string());
        }
    }

    Ok(PatchResult {
        applied: applied_names,
        failed: failed_names,
    })
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
    hints.iter().any(|h| content.contains(h))
}

fn build_replacement(patch: &JsPatch, matched_text: &str) -> Result<String> {
    let mut replacement = patch.replacement_template.to_string();
    if let Some(extractor) = &patch.field_extractor {
        let caps = extractor
            .captures(matched_text)
            .ok_or_else(|| YouModError::PatchNotMatched {
                name: patch.name.to_string(),
            })?;
        let field = caps
            .get(1)
            .ok_or_else(|| YouModError::PatchNotMatched {
                name: patch.name.to_string(),
            })?;
        replacement = replacement.replace("<field>", field.as_str());
    }
    Ok(replacement)
}

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
            && (name == "index.js"
                || (name.starts_with("app-") && name.ends_with(".bundle.js")))
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
        let file_path = dir.join(name);
        fs::write(&file_path, content).unwrap();
    }

    #[test]
    fn test_apply_all_patches_to_mock_files() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        let index_js = r#"
registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{let t=e.updateInfo.url}))))"#;
        create_test_js_file(unpacked, "index.js", index_js);

        let bundle_js = concat!(
            r#"class ApiService{getUserAccount(){return this.#x.fetch({endpoint:"/v3/account","#,
            r#"method:"GET",name:"/v3/account",collectMetrics:0})}"#,
            r#"setAccountWandBrandExperience(){return this.#x.post("/v3/account/brand_experience_wand")}}"#
        );
        create_test_js_file(unpacked, "app-1234.bundle.js", bundle_js);

        let patches: Vec<&JsPatch> = PATCHES.iter().collect();
        let result = patch_js_files(unpacked, &patches).unwrap();

        assert_eq!(result.applied.len(), 3);
        assert!(result.applied.iter().any(|n| n.contains("getUserAccount")));
        assert!(result.applied.iter().any(|n| n.contains("setAccountWandBrandExperience")));
        assert!(result.applied.iter().any(|n| n.contains("Disable Updates")));

        let modified_bundle = fs::read_to_string(unpacked.join("app-1234.bundle.js")).unwrap();
        assert!(modified_bundle.contains(r#"subscription={period:"yearly",state:"active"}"#));

        let modified_index = fs::read_to_string(unpacked.join("index.js")).unwrap();
        assert!(modified_index.contains("e=>null"));
    }

    #[test]
    fn test_no_match_returns_failed() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        let unrelated = "console.log('hello');";
        create_test_js_file(unpacked, "app-test.bundle.js", unrelated);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert_eq!(result.applied.len(), 0);
        assert_eq!(result.failed.len(), 3);
    }

    #[test]
    fn test_candidate_file_filter() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        let not_index = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{}))))"#;
        create_test_js_file(unpacked, "other.bundle.js", not_index);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert!(result.failed.iter().any(|n| n.contains("Disable Updates")));
    }

    #[test]
    fn test_search_hints_any_not_all() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        let content = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{}))))"#;
        create_test_js_file(unpacked, "index.js", content);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        let update_patches = result.applied.iter().filter(|n| n.contains("Disable")).count();
        assert_eq!(update_patches, 1, "Should match with search hint present");
    }

    #[test]
    fn test_non_candidate_files_skipped() {
        let tmp = TempDir::new().unwrap();
        let unpacked = tmp.path();

        let content = r#"getUserAccount(){return this.#x.fetch({endpoint:"/v3/account"})}"#;
        create_test_js_file(unpacked, "some-random.js", content);
        create_test_js_file(unpacked, "library.js", content);

        let result = patch_js_files(unpacked, &all_patches()).unwrap();
        assert_eq!(result.applied.len(), 0, "Non-candidate files should be skipped");
    }
}
