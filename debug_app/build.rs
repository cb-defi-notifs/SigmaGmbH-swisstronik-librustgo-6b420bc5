use std::env;

fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());

    // Link enclave
    println!("cargo:rustc-link-search=native=../sgx-artifacts/lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    // Link libraries
    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
}