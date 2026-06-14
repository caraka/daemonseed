fn main() {
    // The software renderer has no system-font access, so fonts must be embedded
    // at compile time (pre-rendered into the binary). This makes the binary
    // self-contained and identical headless vs windowed. See ISA Decisions.
    let config = slint_build::CompilerConfiguration::new()
        .embed_resources(slint_build::EmbedResourcesKind::EmbedForSoftwareRenderer);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile ui/app.slint");
}
