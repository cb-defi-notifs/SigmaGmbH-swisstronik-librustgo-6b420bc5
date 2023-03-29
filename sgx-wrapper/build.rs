use std::env;

fn main () {
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rustc-link-search=native=../sgx-artifacts/lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native=/opt/intel/sgxsdk/lib64");
    match is_sim.as_ref() {
        "SW" => println!("cargo:rustc-link-lib=dylib=sgx_urts_sim"),
        "HW" => println!("cargo:rustc-link-lib=dylib=sgx_urts"),
        _    => println!("cargo:rustc-link-lib=dylib=sgx_urts"), // Treat undefined as HW
    }
}