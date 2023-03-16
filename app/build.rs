use std::env;

fn main () {
    println!("cargo:rustc-link-search=native=../sgx-artifacts/lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native=/opt/intel/sgxsdk/lib64");
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
}