//! Minimal libcuda (driver API) wrapper loaded with `dlopen`. Used only by the test hog and
//! `memguard doctor --probe`; the daemon never loads libcuda.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};

type InitFn = unsafe extern "C" fn(c_uint) -> c_int;
type DevGetFn = unsafe extern "C" fn(*mut c_int, c_int) -> c_int;
type CtxRetainFn = unsafe extern "C" fn(*mut *mut c_void, c_int) -> c_int;
type CtxSetFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type MemAllocFn = unsafe extern "C" fn(*mut u64, usize) -> c_int;
type MemFreeFn = unsafe extern "C" fn(u64) -> c_int;
type MemAllocManagedFn = unsafe extern "C" fn(*mut u64, usize, c_uint) -> c_int;
type MemAllocHostFn = unsafe extern "C" fn(*mut *mut c_void, usize) -> c_int;
type MemFreeHostFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type MemsetFn = unsafe extern "C" fn(u64, u8, usize) -> c_int;
type SyncFn = unsafe extern "C" fn() -> c_int;
type MemGetInfoFn = unsafe extern "C" fn(*mut usize, *mut usize) -> c_int;
type ErrStrFn = unsafe extern "C" fn(c_int, *mut *const c_char) -> c_int;

pub struct Cuda {
    _lib: super::Library,
    init: InitFn,
    dev_get: DevGetFn,
    ctx_retain: CtxRetainFn,
    ctx_set: CtxSetFn,
    mem_alloc: MemAllocFn,
    mem_free: MemFreeFn,
    mem_alloc_managed: MemAllocManagedFn,
    mem_alloc_host: MemAllocHostFn,
    mem_free_host: MemFreeHostFn,
    memset: MemsetFn,
    sync: SyncFn,
    mem_get_info: MemGetInfoFn,
    err_str: ErrStrFn,
}

unsafe fn sym<T: Copy>(lib: *mut c_void, name: &CStr) -> Result<T, String> {
    let p = libc::dlsym(lib, name.as_ptr());
    if p.is_null() {
        return Err(format!("missing symbol {}", name.to_string_lossy()));
    }
    Ok(std::mem::transmute_copy::<*mut c_void, T>(&p))
}

impl Cuda {
    pub fn load() -> Result<Cuda, String> {
        // SAFETY: dlopen/dlsym with valid names; signatures match the CUDA driver API.
        unsafe {
            let lib = libc::dlopen(c"libcuda.so.1".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if lib.is_null() {
                let e = libc::dlerror();
                let msg = if e.is_null() {
                    "unknown".into()
                } else {
                    CStr::from_ptr(e).to_string_lossy().into_owned()
                };
                return Err(format!("dlopen libcuda.so.1 failed: {msg}"));
            }
            let library = super::Library(lib);
            Ok(Cuda {
                _lib: library,
                init: sym(lib, c"cuInit")?,
                dev_get: sym(lib, c"cuDeviceGet")?,
                ctx_retain: sym(lib, c"cuDevicePrimaryCtxRetain")?,
                ctx_set: sym(lib, c"cuCtxSetCurrent")?,
                mem_alloc: sym(lib, c"cuMemAlloc_v2")?,
                mem_free: sym(lib, c"cuMemFree_v2")?,
                mem_alloc_managed: sym(lib, c"cuMemAllocManaged")?,
                mem_alloc_host: sym(lib, c"cuMemAllocHost_v2")?,
                mem_free_host: sym(lib, c"cuMemFreeHost")?,
                memset: sym(lib, c"cuMemsetD8_v2")?,
                sync: sym(lib, c"cuCtxSynchronize")?,
                mem_get_info: sym(lib, c"cuMemGetInfo_v2")?,
                err_str: sym(lib, c"cuGetErrorString")?,
            })
        }
    }

    fn check(&self, rc: c_int, what: &str) -> Result<(), String> {
        if rc == 0 {
            return Ok(());
        }
        let mut p: *const c_char = std::ptr::null();
        // SAFETY: valid out pointer; string is static.
        let msg = unsafe {
            if (self.err_str)(rc, &mut p) == 0 && !p.is_null() {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            } else {
                "unknown".into()
            }
        };
        Err(format!("{what} failed: {msg} ({rc})"))
    }

    /// cuInit + primary context on device 0.
    pub fn init_primary(&self) -> Result<(), String> {
        // SAFETY: straightforward driver API calls with valid pointers.
        unsafe {
            self.check((self.init)(0), "cuInit")?;
            let mut dev: c_int = 0;
            self.check((self.dev_get)(&mut dev, 0), "cuDeviceGet")?;
            let mut ctx: *mut c_void = std::ptr::null_mut();
            self.check((self.ctx_retain)(&mut ctx, dev), "cuDevicePrimaryCtxRetain")?;
            self.check((self.ctx_set)(ctx), "cuCtxSetCurrent")
        }
    }

    pub fn mem_alloc(&self, bytes: usize) -> Result<u64, String> {
        let mut p: u64 = 0;
        // SAFETY: valid out pointer.
        self.check(unsafe { (self.mem_alloc)(&mut p, bytes) }, "cuMemAlloc")?;
        Ok(p)
    }

    pub fn mem_free(&self, ptr: u64) {
        // SAFETY: pointer came from mem_alloc/mem_alloc_managed.
        unsafe {
            (self.mem_free)(ptr);
        }
    }

    pub fn mem_alloc_managed(&self, bytes: usize) -> Result<u64, String> {
        let mut p: u64 = 0;
        // SAFETY: valid out pointer; flag 1 = CU_MEM_ATTACH_GLOBAL.
        self.check(
            unsafe { (self.mem_alloc_managed)(&mut p, bytes, 1) },
            "cuMemAllocManaged",
        )?;
        Ok(p)
    }

    pub fn mem_alloc_host(&self, bytes: usize) -> Result<*mut u8, String> {
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: valid out pointer.
        self.check(
            unsafe { (self.mem_alloc_host)(&mut p, bytes) },
            "cuMemAllocHost",
        )?;
        Ok(p as *mut u8)
    }

    pub fn mem_free_host(&self, p: *mut u8) {
        // SAFETY: pointer came from mem_alloc_host.
        unsafe {
            (self.mem_free_host)(p as *mut c_void);
        }
    }

    pub fn memset_d8(&self, ptr: u64, val: u8, bytes: usize) -> Result<(), String> {
        // SAFETY: device pointer and length from a prior allocation.
        self.check(unsafe { (self.memset)(ptr, val, bytes) }, "cuMemsetD8")
    }

    pub fn sync(&self) -> Result<(), String> {
        // SAFETY: no arguments.
        self.check(unsafe { (self.sync)() }, "cuCtxSynchronize")
    }

    pub fn mem_get_info(&self) -> Result<(u64, u64), String> {
        let (mut f, mut t) = (0usize, 0usize);
        // SAFETY: valid out pointers.
        self.check(
            unsafe { (self.mem_get_info)(&mut f, &mut t) },
            "cuMemGetInfo",
        )?;
        Ok((f as u64, t as u64))
    }
}
