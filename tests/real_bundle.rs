//! End-to-end validation of the JavaScript patches against a real Wand bundle.
//!
//! Ignored by default: it needs a Wand installation. Point `YOUMOD_WAND_ASAR` at
//! `<app dir>\resources\app.asar` — a pristine `app.asar.backup` is ideal, since
//! patching is always applied to a freshly extracted archive — and run
//!
//! ```text
//! $env:YOUMOD_WAND_ASAR = "$env:LOCALAPPDATA\WeMod\app-12.61.0\resources\app.asar.backup"
//! cargo test --test real_bundle -- --ignored --nocapture
//! ```
//!
//! Every root-level `.js` entry is extracted to a temporary directory, the real
//! [`patch_js_files`] pipeline runs over it, and the result is checked three
//! ways: each patch reports success, every rewritten bundle still parses as
//! JavaScript, and a second run changes nothing.

use asar_rust::AsarArchive;
use oxc_allocator::Allocator;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use you_mod::js_edit;
use you_mod::patcher::patch_js_files;
use you_mod::patches::PATCHES;

/// A payload is only correct if it kept the original request expression, so
/// each expectation embeds the real call from Wand 12.61.
const EXPECTED: &[(&str, &str)] = &[
    (
        "getUserAccount (Pro spoof)",
        concat!(
            r#"getUserAccount(){return (this.#e.fetch({endpoint:"/v3/account",method:"GET","#,
            r#"name:"/v3/account",collectMetrics:!1})).then((response)=>"#,
        ),
    ),
    (
        "setAccountWandBrandExperience (Pro spoof)",
        r#"setAccountWandBrandExperience(){return (this.#e.post("/v3/account/brand_experience_wand")).then((response)=>"#,
    ),
    (
        "setAccountLanguage (Pro spoof)",
        r#"setAccountLanguage(e,t){return (this.#e.post("/v3/account/language",{tag:e,auto:t})).then((response)=>"#,
    ),
    (
        "setAccountReducer (Pro spoof)",
        r#"account:((account)=>account&&"object"==typeof account?{...account,subscription:{period:"yearly",state:"active"}}:account)(e)"#,
    ),
    (
        "disableNativeRemotePairing (Pro spoof)",
        r#"requestRemoteAuthCode(){return Promise.reject(new Error("you-mod: native mobile pairing disabled"))}"#,
    ),
];

/// The two methods the pre-12.61 patches rebuilt by hand; the structural
/// rewrite must leave their request bodies byte-identical instead.
const PRESERVED: &[&str] = &[
    r#"endpoint:"/v3/account",method:"GET",name:"/v3/account",collectMetrics:!1"#,
    r#"/v3/account/brand_experience_wand"#,
];

#[test]
#[ignore = "needs a real Wand installation (set YOUMOD_WAND_ASAR)"]
fn patches_a_real_wand_bundle() {
    let Some(asar_path) = std::env::var_os("YOUMOD_WAND_ASAR") else {
        eprintln!("YOUMOD_WAND_ASAR is not set - nothing to validate");
        return;
    };
    let asar_path = PathBuf::from(asar_path);
    assert!(asar_path.is_file(), "not a file: {}", asar_path.display());

    let tmp = TempDir::new().unwrap();
    let extracted = extract_root_scripts(&asar_path, tmp.path());
    println!("extracted {extracted} root .js entries");

    let patches: Vec<&you_mod::patches::JsPatch> = PATCHES.iter().collect();
    let result = patch_js_files(tmp.path(), &patches).expect("patching a real bundle");

    println!("\napplied: {:?}", result.applied);
    assert_eq!(
        result.failed,
        Vec::<String>::new(),
        "every patch must find its anchor in Wand 12.61"
    );

    let patched_files = modified_scripts(tmp.path());
    println!("rewrote {} bundle(s)", patched_files.len());
    for path in &patched_files {
        println!("  rewrote {}", path.file_name().unwrap().to_string_lossy());
    }
    // Wand ships each site-bearing bundle twice, once for the main window
    // (`app-*`) and once for the overlay (`overlay-*`).
    assert!(
        patched_files.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("overlay-"))
        }),
        "the overlay copies of the bundles were not patched"
    );
    assert!(
        patched_files.len() >= 4,
        "expected at least the four site-bearing bundles to be rewritten"
    );

    for path in &patched_files {
        let content = fs::read_to_string(path).unwrap();

        let allocator = Allocator::default();
        assert!(
            js_edit::parse(&allocator, &content).is_some(),
            "{} no longer parses after patching",
            path.display()
        );
    }

    let all: String = patched_files
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();

    for (name, expected) in EXPECTED {
        assert!(
            all.contains(expected),
            "{name}: payload missing from every patched bundle"
        );
        println!("ok  {name}");
    }

    for preserved in PRESERVED {
        assert!(
            all.contains(preserved),
            "the original request expression was rewritten: {preserved}"
        );
    }

    let before: Vec<(PathBuf, String)> = patched_files
        .iter()
        .map(|path| (path.clone(), fs::read_to_string(path).unwrap()))
        .collect();
    let second = patch_js_files(tmp.path(), &patches).expect("second pass");
    assert_eq!(
        second.failed,
        Vec::<String>::new(),
        "a second pass must recognise the payloads it wrote"
    );
    for (path, content) in &before {
        assert_eq!(
            &fs::read_to_string(path).unwrap(),
            content,
            "{} changed on a second pass",
            path.display()
        );
    }

    println!("\nall payloads present, output parses, second pass is a no-op");
}

/// Extracts every root-level `.js` entry, which is where Wand keeps its bundles.
fn extract_root_scripts(asar_path: &Path, dest: &Path) -> usize {
    let archive = AsarArchive::open(asar_path).expect("open the asar");
    let entries = archive.list().expect("list the asar");

    let mut count = 0;
    for entry in entries.iter() {
        let name = entry.trim_start_matches('/');
        if !name.ends_with(".js") || name.contains('/') {
            continue;
        }
        let data = archive.extract_file(name).expect("extract a bundle");
        fs::write(dest.join(name), data).expect("write a bundle");
        count += 1;
    }
    count
}

fn modified_scripts(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("js"))
                && fs::read_to_string(path).is_ok_and(|content| {
                    content.contains("state:\"active\"")
                        || content.contains("native mobile pairing")
                })
        })
        .collect();
    paths.sort();
    paths
}
