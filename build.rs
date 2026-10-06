fn main() {
    // Expose the build target triple so an installer can refuse a tool
    // pack built for a foreign platform. `TARGET` is set for build scripts
    // but not for normal compilation, hence the relay.
    println!(
        "cargo:rustc-env=AIVYX_PACK_BUILD_TARGET={}",
        std::env::var("TARGET").expect("cargo sets TARGET for build scripts")
    );
}
