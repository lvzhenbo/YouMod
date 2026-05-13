use std::fs;
use tempfile::TempDir;
use you_mod::patcher;
use you_mod::patches::PATCHES;

#[test]
fn test_extract_patch_repack_roundtrip() {
    let tmp = TempDir::new().unwrap();

    let unpacked_src = tmp.path().join("src");
    fs::create_dir_all(&unpacked_src).unwrap();

    let bundle_js = concat!(
        r#"class A{getUserAccount(){return this.#x.fetch({endpoint:"/v3/account","#,
        r#"method:"GET",name:"/v3/account",collectMetrics:0})}"#,
        r#"setAccountWandBrandExperience(){return this.#x.post("/v3/account/brand_experience_wand")}}"#
    );
    fs::write(unpacked_src.join("app-1.bundle.js"), bundle_js).unwrap();

    let index_js = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{let t=e.updateInfo.url}))))"#;
    fs::write(unpacked_src.join("index.js"), index_js).unwrap();

    let asar_path = tmp.path().join("test.asar");
    asar_rust::create_package(&unpacked_src, &asar_path).unwrap();

    assert!(asar_path.exists());

    let extracted = tmp.path().join("extracted");
    asar_rust::extract_all(&asar_path, &extracted).unwrap();

    let patches: Vec<&you_mod::patches::JsPatch> = PATCHES.iter().collect();
    let result = patcher::patch_js_files(&extracted, &patches).unwrap();
    assert_eq!(result.applied.len(), 3);

    let repacked = tmp.path().join("repacked.asar");
    let options = asar_rust::CreateOptions {
        dot: false,
        ordering: None,
        unpack: None,
        unpack_dir: None,
    };
    asar_rust::create_package_with_options(&extracted, &repacked, options).unwrap();

    let files = asar_rust::list_package(&repacked, None).unwrap();
    assert!(!files.is_empty());
}
