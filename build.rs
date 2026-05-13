use std::path::Path;
use std::process::Command;

fn main() {
    let dll = Path::new("version-dll/target/release/version.dll");

    // Only rebuild version-dll when the output doesn't exist or sources are newer
    let needs_rebuild = !dll.exists() || !is_dll_fresh(dll);

    if needs_rebuild {
        let status = Command::new("cargo")
            .args(["build", "--release"])
            .current_dir("version-dll")
            .status()
            .expect("Failed to build version-dll");

        if !status.success() {
            panic!("version-dll build failed");
        }
    }

    let dll_path = std::fs::canonicalize(dll).expect("version.dll not found after build");

    println!("cargo:rerun-if-changed=version-dll/");
    println!("cargo:rustc-env=PROXY_DLL_PATH={}", dll_path.display());
}

fn is_dll_fresh(dll: &Path) -> bool {
    let Ok(dll_time) = std::fs::metadata(dll).and_then(|m| m.modified()) else {
        return false;
    };

    // Check key source files that would invalidate the DLL
    let sources = ["version-dll/Cargo.toml", "version-dll/src/lib.rs"];

    for src in &sources {
        let src_path = Path::new(src);
        if src_path.exists() {
            if let Ok(src_time) = std::fs::metadata(src_path).and_then(|m| m.modified()) {
                if src_time > dll_time {
                    return false;
                }
            }
        }
    }

    true
}
