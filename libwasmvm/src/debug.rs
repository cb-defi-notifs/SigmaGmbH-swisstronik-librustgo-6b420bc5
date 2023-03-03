// This is a testing file. It will be removed soon
// TODO: remove this file

use crate::{UnmanagedVector, U8SliceView, GoError};

#[repr(C)]
#[derive(Clone)]
pub struct DebugQuerier {
    pub state: *const debug_t,
    pub vtable: Debug_vtable,
}

#[repr(C)]
#[derive(Clone)]
pub struct debug_t {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone)]
pub struct Debug_vtable {
    // We return errors through the return buffer, but may return non-zero error codes on panic
    pub debug: extern "C" fn(
        *const debug_t,
        *mut UnmanagedVector, // result output
        *mut UnmanagedVector, // error message output
    ) -> i32,
}

impl DebugQuerier {
    /// Calls go code via vtable and trying to decode an error
    #[no_mangle]
    pub extern "C" fn debug(self) {
        let mut output = UnmanagedVector::default();
        let mut error_msg = UnmanagedVector::default();

        let go_result: GoError = (self.vtable.debug)(
            self.state,
            &mut output as *mut UnmanagedVector,
            &mut error_msg as *mut UnmanagedVector,
        )
        .into();

        let output = output.consume();
        let error_msg = error_msg.consume();

        println!("output: {:?}", output);
        println!("error: {:?}", error_msg);
    }
}

#[no_mangle]
pub extern "C" fn debug_error_vtable(dq: DebugQuerier) {
    dq.debug()
}
