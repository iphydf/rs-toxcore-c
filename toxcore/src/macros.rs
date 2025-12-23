macro_rules! ffi_call {
    ($func:ident, $ok_variant:path $(, $args:expr)*) => {
        {
            let mut err = $ok_variant;
            // The compiler will infer the type of err from the assignment
            let res = unsafe { ffi::$func($($args,)* &mut err) };
            if err == $ok_variant {
                Ok(res)
            } else {
                Err(err)
            }
        }
    };
}

macro_rules! ffi_call_unit {
    ($($args:tt)*) => {
        ffi_call!($($args)*).map(|_| ())
    };
}

macro_rules! ffi_get_vec {
    ($func:ident, $size_func:ident, $ok_variant:path $(, $args:expr)*) => {
        {
            let mut err = $ok_variant;
            let size = unsafe { ffi::$size_func($($args,)* &mut err) };
            if err != $ok_variant {
                Err(err)
            } else {
                let mut buf = vec![0u8; size];
                unsafe { ffi::$func($($args,)* buf.as_mut_ptr(), &mut err) };
                if err == $ok_variant {
                    Ok(buf)
                } else {
                    Err(err)
                }
            }
        }
    };
}

macro_rules! ffi_get_vec_simple {
    ($func:ident, $size_func:ident, $type:ty $(, $args:expr)*) => {
        {
            let size = unsafe { ffi::$size_func($($args),*) };
            if size == 0 {
                Vec::new()
            } else {
                let mut buf = vec![<$type>::default(); size as usize];
                unsafe { ffi::$func($($args,)* buf.as_mut_ptr()) };
                buf
            }
        }
    };
}

macro_rules! ffi_bool {
    ($func:ident $(, $args:expr)*) => {
        unsafe { ffi::$func($($args),*) }
    };
}

macro_rules! ffi_get_array {
    ($func:ident, $ok_variant:path, $len:expr $(, $args:expr)*) => {
        {
            let mut err = $ok_variant;
            let mut buf = [0u8; $len];
            if unsafe { ffi::$func($($args,)* buf.as_mut_ptr(), &mut err) } {
                Ok(buf)
            } else {
                Err(err)
            }
        }
    };
}
