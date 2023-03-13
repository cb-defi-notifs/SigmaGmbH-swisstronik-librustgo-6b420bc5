extern crate protoc_rust;

use std::env;
use protoc_rust::Customize;


fn main() {
    println!("cargo:rustc-link-search={}", "./");
    println!("cargo:rustc-link-lib=dylib=sgx_evm");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let generated = cbindgen::generate(crate_dir).expect("Unable to generate bindings");
    generated.write_to_file("bindings.h");
    generated.write_to_file("../internal/api/bindings.h");

    protoc_rust::Codegen::new()
        .out_dir("src/protobuf_generated")
        .includes(&["./protobuf_contracts"])
        .inputs(&["./protobuf_contracts/ffi.proto"])
        .customize(Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .run()
        .expect("protoc");
}
