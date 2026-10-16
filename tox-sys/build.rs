use std::env;
use std::path::PathBuf;

fn main() {
    let header = "../toxcore/src/wrapper.h";
    println!("cargo:rerun-if-changed={header}");
    let toxcore = pkg_config::probe_library("toxcore").expect("toxcore not found");
    bindgen::Builder::default()
        .header(header)
        .clang_args(toxcore.include_paths.iter().map(|p| format!("-I{}", p.display())))
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
        .allowlist_function("tox_.*")
        .allowlist_function("toxav_.*")
        .allowlist_type("Tox_.*")
        .allowlist_type("Toxav_.*")
        .allowlist_var("TOX_.*")
        .allowlist_var("TOXAV_.*")
        .generate()
        .expect("bindgen failed")
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("can't write bindings");
}
