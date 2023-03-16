extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &str = "enclave.signed.so";

extern "C" {
    fn handle_request(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t
    ) -> sgx_status_t;
}

/// Initializes SGX enclave
pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags:0, xfrm: 0 }, misc_select: 0 };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr
    )
}

/// Makes a call to a provided enclave
pub fn call_enclave(enclave: &SgxEnclave) {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        handle_request(
            enclave.geteid(),
            &mut retval,
        )
    };
    println!("Enclave call result: {:?}", result);
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            panic!("{}", x.as_str());
        },
    };

    call_enclave(&enclave);
}