use errno::{set_errno, Errno};
#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use thiserror::Error;
use crate::memory::UnmanagedVector;
use std::string::String;

#[derive(Error, Debug)]
pub enum RustError {
    #[error("Empty argument: {}", name)]
    EmptyArg {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    /// Whenever UTF-8 bytes cannot be decoded into a unicode string, e.g. in String::from_utf8 or str::from_utf8.
    #[error("Cannot decode UTF8 bytes into string: {}", msg)]
    InvalidUtf8 {
        msg: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Ran out of gas")]
    OutOfGas {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Caught panic")]
    Panic {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Null/Nil argument: {}", name)]
    UnsetArg {
        name: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Error calling the VM: {}", msg)]
    VmErr {
        msg: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Error decoding protobuf: {}", msg)]
    ProtobufDecodeError {
        msg: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },

}

impl RustError {
    pub fn empty_arg<T: Into<String>>(name: T) -> Self {
        RustError::EmptyArg {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn invalid_utf8<S: ToString>(msg: S) -> Self {
        RustError::InvalidUtf8 {
            msg: msg.to_string(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn protobuf_decode<S: ToString>(msg: S) -> Self {
        RustError::ProtobufDecodeError {
            msg: msg.to_string(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn panic() -> Self {
        RustError::Panic {
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn unset_arg<T: Into<String>>(name: T) -> Self {
        RustError::UnsetArg {
            name: name.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn vm_err<S: ToString>(msg: S) -> Self {
        RustError::VmErr {
            msg: msg.to_string(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn out_of_gas() -> Self {
        RustError::OutOfGas {
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }
}


impl From<std::str::Utf8Error> for RustError {
    fn from(source: std::str::Utf8Error) -> Self {
        RustError::invalid_utf8(source)
    }
}

impl From<std::string::FromUtf8Error> for RustError {
    fn from(source: std::string::FromUtf8Error) -> Self {
        RustError::invalid_utf8(source)
    }
}

/// cbindgen:prefix-with-name
#[repr(i32)]
enum ErrnoValue {
    Success = 0,
    Other = 1,
    OutOfGas = 2,
}

/// If `result` is Ok, this returns the Ok value and clears [errno].
/// Otherwise it returns the default value, writes the error message to `error_msg` and sets [errno].
///
/// [errno]: https://utcc.utoronto.ca/~cks/space/blog/programming/GoCgoErrorReturns
pub fn handle_c_error_default<T>(
    result: Result<T, RustError>,
    error_msg: Option<&mut UnmanagedVector>,
) -> T
    where
        T: Default,
{
    match result {
        Ok(value) => {
            clear_error();
            value
        }
        Err(error) => {
            set_error(error, error_msg);
            Default::default()
        }
    }
}

pub fn set_error(err: RustError, error_msg: Option<&mut UnmanagedVector>) {
    if let Some(error_msg) = error_msg {
        if error_msg.is_some() {
            panic!(
                "There is an old error message in the given pointer that has not been \
                cleaned up. Error message pointers should not be reused for multiple calls."
            )
        }

        let msg: Vec<u8> = err.to_string().into();
        *error_msg = UnmanagedVector::new(Some(msg));
    } else {
        // The caller provided a nil pointer for the error message.
        // That's not nice but we can live with it.
    }

    let errno = match err {
        RustError::OutOfGas { .. } => ErrnoValue::OutOfGas,
        _ => ErrnoValue::Other,
    } as i32;
    set_errno(Errno(errno));
}

pub fn clear_error() {
    set_errno(Errno(ErrnoValue::Success as i32));
}

#[cfg(test)]
mod tests {
    use super::*;
    use errno::errno;
    use std::str;

    #[test]
    fn empty_arg_works() {
        let error = RustError::empty_arg("gas");
        match error {
            RustError::EmptyArg { name, .. } => {
                assert_eq!(name, "gas");
            }
            _ => panic!("expect different error"),
        }
    }

    #[test]
    fn invalid_utf8_works_for_strings() {
        let error = RustError::invalid_utf8("my text");
        match error {
            RustError::InvalidUtf8 { msg, .. } => {
                assert_eq!(msg, "my text");
            }
            _ => panic!("expect different error"),
        }
    }

    #[test]
    fn invalid_utf8_works_for_errors() {
        let original = String::from_utf8(vec![0x80]).unwrap_err();
        let error = RustError::invalid_utf8(original);
        match error {
            RustError::InvalidUtf8 { msg, .. } => {
                assert_eq!(msg, "invalid utf-8 sequence of 1 bytes from index 0");
            }
            _ => panic!("expect different error"),
        }
    }

    #[test]
    fn panic_works() {
        let error = RustError::panic();
        match error {
            RustError::Panic { .. } => {}
            _ => panic!("expect different error"),
        }
    }

    #[test]
    fn unset_arg_works() {
        let error = RustError::unset_arg("gas");
        match error {
            RustError::UnsetArg { name, .. } => {
                assert_eq!(name, "gas");
            }
            _ => panic!("expect different error"),
        }
    }

    #[test]
    fn vm_err_works_for_strings() {
        let error = RustError::vm_err("my text");
        match error {
            RustError::VmErr { msg, .. } => {
                assert_eq!(msg, "my text");
            }
            _ => panic!("expect different error"),
        }
    }

    // Tests of `impl From<X> for RustError` converters

    #[test]
    fn from_std_str_utf8error_works() {
        let error: RustError = str::from_utf8(b"Hello \xF0\x90\x80World")
            .unwrap_err()
            .into();
        match error {
            RustError::InvalidUtf8 { msg, .. } => {
                assert_eq!(msg, "invalid utf-8 sequence of 3 bytes from index 6")
            }
            _ => panic!("expect different error"),
        }
    }

    #[test]
    fn from_std_string_fromutf8error_works() {
        let error: RustError = String::from_utf8(b"Hello \xF0\x90\x80World".to_vec())
            .unwrap_err()
            .into();
        match error {
            RustError::InvalidUtf8 { msg, .. } => {
                assert_eq!(msg, "invalid utf-8 sequence of 3 bytes from index 6")
            }
            _ => panic!("expect different error"),
        }
    }
}
