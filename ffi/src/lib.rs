pub use {crate::error::LastError, allo_isolate, async_std, log, once_cell::sync::OnceCell};

mod error;

/// A simple macro to match on a result and if there is an error it returns -1 or your custom error
#[doc(hidden)]
#[macro_export]
macro_rules! result {
    ($result:expr) => {
        $crate::result!($result, -1);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                $crate::log::error!("{:?}", e);
                return $error;
            }
        }
    };
}

/// A macro to convert c_char pointer to rust's str type
#[doc(hidden)]
#[macro_export]
macro_rules! cstr {
    ($ptr:expr, allow_null) => {
        if $ptr.is_null() {
            None
        } else {
            Some($crate::cstr!($ptr))
        }
    };
    ($ptr:expr) => {
        $crate::cstr!($ptr, 0xbadd);
    };
    ($ptr:expr, $error:expr) => {
        unsafe {
            if $ptr.is_null() {
                return $error;
            }
            $crate::result!(::std::ffi::CStr::from_ptr($ptr).to_str(), $error)
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! static_client {
    () => {
        $crate::static_client!(err = 0xdead);
    };
    (err = $err:expr) => {
        match CLIENT.get() {
            Some(client) => client,
            None => {
                return $err;
            }
        }
    };
}

/// A helper macro to write the ffi functions for you.
#[macro_export]
macro_rules! gen_ffi {
    (
        $(#[$outer:meta])*
        $struct: ident :: $method: ident => fn $name: ident(
            $($param: ident : $ty: ty = $val: expr),*
        ) -> $ret: ty;
    ) => {
        $(#[$outer])*
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn $name(port: i64, $($param: $ty),*) -> i32 {
            let isolate = $crate::allo_isolate::Isolate::new(port);
            $(
                let $param = $val;
            )*
            let client = $crate::static_client!();
            let ffi_struct = $struct::new(client);
            let t = isolate.task(async move {
                match $struct::$method(&ffi_struct, $($param),*).await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        $crate::log::error!("{:?}: {:?}", stringify!($struct::$method), e);
                        None
                    }
                }
            });
            $crate::async_std::task::spawn(t);
            1
        }
    };
     (
        $(
            $(#[$outer:meta])*
            $struct: ident :: $method: ident => fn $name: ident(
                $($param: ident : $ty: ty = $val: expr),*
            ) -> $ret: ty;
        )+
    ) => {
        $(
            $crate::gen_ffi!(
                $(#[$outer])*
                $struct::$method => fn $name($($param: $ty = $val),*) -> $ret;
            );
        )+
    };

    (
        client = $client: ty;
        $(
            $(#[$outer:meta])*
            $struct: ident :: $method: ident => fn $name: ident(
                $($param: ident : $ty: ty = $val: expr),*
            ) -> $ret: ty;
        )+
    ) => {
        $crate::gen_ffi!(client = $client);
        $(
            $crate::gen_ffi!(
                $(#[$outer])*
                $struct::$method => fn $name($($param: $ty = $val),*) -> $ret;
            );
        )+
    };

    (client = $c: ty) => {
        use $crate::async_std::sync::RwLock;
        /// cbindgen:ignore
        static CLIENT: $crate::OnceCell<RwLock<$c>> = $crate::OnceCell::new();

        /// Setup the Sunshine Client using the provided path as the base path and with chainspec.
        ///
        /// ### Safety
        /// This assumes that the path non-null c string.
        /// chain_spec could be null.
        /// url could also be null.
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_init(
            port: i64,
            path: *const ::std::os::raw::c_char,
            chain_spec: *const ::std::os::raw::c_char,
            url: *const ::std::os::raw::c_char,
        ) -> i32 {
            // check if we already created the client, and return `0xdead >> 0x01`
            // if it is already created to avoid any unwanted work
            if CLIENT.get().is_some() {
                return 0xdead >> 0x01;
            }
            /// Setup a panic hook with the logger.
            $crate::panic_hook!();
            let root = ::std::path::PathBuf::from(cstr!(path));
            let chain_spec = cstr!(chain_spec, allow_null);
            let url = cstr!(url, allow_null);
            let isolate = $crate::allo_isolate::Isolate::new(port);
            let t = isolate.task(async move {
                let client = match (chain_spec, url) {
                    // if we suplied both, use chain spec.
                    (Some(spec), _) => <$c>::new(&root, ::std::path::PathBuf::from(spec).as_path()).await,
                    (None, Some(rpc)) => <$c>::new(&root, rpc).await,
                    _ => return 0xdead >> 0x03,
                };
                let client = $crate::result!(client, 0xdead >> 0x02);
                $crate::result!(CLIENT.set(RwLock::new(client)).map_err(|_| ()), 0xdead >> 0x01);
                1
            });
            $crate::async_std::task::spawn(t);
            1
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! panic_hook {
    () => {
        ::std::panic::set_hook(::std::boxed::Box::new(|panic_info| {
            $crate::log::error!("🔥 !! PANIC !! 🔥");
            if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                $crate::log::error!("{}", s);
                if let Some(args) = panic_info.message() {
                    $crate::log::error!("with {}", args);
                }
                if let Some(loc) = panic_info.location() {
                    $crate::log::error!("at {}", loc);
                }
                println!("panic occurred: {:?}", s);
            } else {
                $crate::log::error!("no info provided for that panic");
                println!("panic occurred but no info ...errr");
            }
        }));
    };
}
