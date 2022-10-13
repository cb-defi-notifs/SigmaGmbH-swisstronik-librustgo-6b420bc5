extern crate protoc_rust;

use std::env;
use protoc_rust::Customize;


fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file("bindings.h");

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
