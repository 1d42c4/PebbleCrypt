fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("ProductName", "PebbleCrypt")
            .set("FileDescription", "PebbleCrypt — File encryption")
            .set("LegalCopyright", "MIT License")
            .set_icon("assets/pebblecrypt.ico");
        res.compile().expect("compile Windows app resources");
    }
}
