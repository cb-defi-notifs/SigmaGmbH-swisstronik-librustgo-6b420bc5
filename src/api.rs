use cosmwasm_std::{Binary, CanonicalAddr, HumanAddr};
use cosmwasm_vm::{Api, FfiError, FfiResult};

use crate::error::GoResult;
use crate::memory::Buffer;

// this represents something passed in from the caller side of FFI
// in this case a struct with go function pointers
#[repr(C)]
pub struct api_t {
    _private: [u8; 0],
}

// These functions should return GoResult but because we don't trust them here, we treat the return value as i32
// and then check it when converting to GoResult manually
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GoApi_vtable {
    pub humanize_address: extern "C" fn(*const api_t, Buffer, *mut Buffer) -> i32,
    pub canonicalize_address: extern "C" fn(*const api_t, Buffer, *mut Buffer) -> i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GoApi {
    pub state: *const api_t,
    pub vtable: GoApi_vtable,
}

// We must declare that these are safe to Send, to use in wasm.
// The known go caller passes in immutable function pointers, but this is indeed
// unsafe for possible other callers.
//
// see: https://stackoverflow.com/questions/50258359/can-a-struct-containing-a-raw-pointer-implement-send-and-be-ffi-safe
unsafe impl Send for GoApi {}

impl Api for GoApi {
    fn canonical_address(&self, human: &HumanAddr) -> FfiResult<CanonicalAddr> {
        let human_bytes = human.as_str().as_bytes();
        let human_bytes = Buffer::from_vec(human_bytes.to_vec());
        let mut output = Buffer::default();
        let go_result: GoResult =
            (self.vtable.canonicalize_address)(self.state, human_bytes, &mut output as *mut Buffer)
                .into();
        let _human = unsafe { human_bytes.consume() };
        let go_result: FfiResult<()> = go_result.into();
        go_result?;
        let canon = if output.ptr.is_null() {
            Vec::new()
        } else {
            // We initialize `output` with a null pointer. if it is not null,
            // that means it was initialized by the go code, with values generated by `memory::allocate_rust`
            unsafe { output.consume() }
        };
        Ok(CanonicalAddr(Binary(canon)))
    }

    fn human_address(&self, canonical: &CanonicalAddr) -> FfiResult<HumanAddr> {
        let canonical = canonical.as_slice();
        let canonical = Buffer::from_vec(canonical.to_vec());
        let mut output = Buffer::default();
        let go_result: GoResult =
            (self.vtable.humanize_address)(self.state, canonical, &mut output as *mut Buffer)
                .into();
        let _canonical = unsafe { canonical.consume() };
        let go_result: FfiResult<()> = go_result.into();
        go_result?;
        let result = if output.ptr.is_null() {
            Vec::new()
        } else {
            // We initialize `output` with a null pointer. if it is not null,
            // that means it was initialized by the go code, with values generated by `memory::allocate_rust`
            unsafe { output.consume() }
        };
        let human = String::from_utf8(result).or(Err(FfiError::Other))?;
        Ok(HumanAddr(human))
    }
}
