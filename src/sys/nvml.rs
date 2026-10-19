//! NVML loaded with `dlopen` at runtime. Only the process lists are used: on GB10 the
//! device-level memory queries return NOT_SUPPORTED, but per-process `usedGpuMemory` works.
//!
//! WARNING: these calls go through the driver's RM lock and can block for the whole duration of
//! another process's allocation ioctl (measured 715 ms for 24 GiB). Never call from the hot loop.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};

pub const NVML_SUCCESS: c_int = 0;
pub const NVML_ERROR_INSUFFICIENT_SIZE: c_int = 7;
pub const NVML_VALUE_NOT_AVAILABLE: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessInfoV3 {
    pub pid: c_uint,
    pub used_gpu_memory: u64,
    pub gpu_instance_id: c_uint,
    pub compute_instance_id: c_uint,
}

const _: () = assert!(std::mem::size_of::<ProcessInfoV3>() == 24);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuProc {
    pub pid: u32,
    pub bytes: u64,
}

type InitFn = unsafe extern "C" fn() -> c_int;
type ShutdownFn = unsafe extern "C" fn() -> c_int;
type CountFn = unsafe extern "C" fn(*mut c_uint) -> c_int;
type HandleFn = unsafe extern "C" fn(c_uint, *mut *mut c_void) -> c_int;
type ProcsFn = unsafe extern "C" fn(*mut c_void, *mut c_uint, *mut ProcessInfoV3) -> c_int;
type DriverVerFn = unsafe extern "C" fn(*mut c_char, c_uint) -> c_int;
type ErrStrFn = unsafe extern "C" fn(c_int) -> *const c_char;

pub struct Nvml {
    _lib: super::Library,
    shutdown: ShutdownFn,
    count: CountFn,
    handle: HandleFn,
    compute: ProcsFn,
    graphics: ProcsFn,
    driver_version: DriverVerFn,
    err_str: ErrStrFn,
    devices: Vec<*mut c_void>,
    scratch: Vec<ProcessInfoV3>,
}

// SAFETY: NVML handles are plain pointers usable from any thread after init.
unsafe impl Send for Nvml {}

unsafe fn sym<T: Copy>(lib: *mut c_void, name: &CStr) -> Result<T, String> {
    let p = libc::dlsym(lib, name.as_ptr());
    if p.is_null() {
        return Err(format!("missing symbol {}", name.to_string_lossy()));
    }
    // SAFETY: caller guarantees T is a function pointer type of the right signature.
    Ok(std::mem::transmute_copy::<*mut c_void, T>(&p))
}

impl Nvml {
    /// dlopen libnvidia-ml.so.1 and initialise. Fails cleanly when the library or driver is absent.
    pub fn load() -> Result<Nvml, String> {
        // SAFETY: dlopen/dlsym with valid C strings; function pointer types match the NVML API.
        unsafe {
            let lib = libc::dlopen(
                c"libnvidia-ml.so.1".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            );
            if lib.is_null() {
                let e = libc::dlerror();
                let msg = if e.is_null() {
                    "unknown".to_string()
                } else {
                    CStr::from_ptr(e).to_string_lossy().into_owned()
                };
                return Err(format!("dlopen libnvidia-ml.so.1 failed: {msg}"));
            }
            // Close the dlopen handle on every missing-symbol or initialization error.
            let library = super::Library(lib);
            let init: InitFn = sym(lib, c"nvmlInit_v2")?;
            let shutdown: ShutdownFn = sym(lib, c"nvmlShutdown")?;
            let count: CountFn = sym(lib, c"nvmlDeviceGetCount_v2")?;
            let handle: HandleFn = sym(lib, c"nvmlDeviceGetHandleByIndex_v2")?;
            let compute: ProcsFn = sym(lib, c"nvmlDeviceGetComputeRunningProcesses_v3")?;
            let graphics: ProcsFn = sym(lib, c"nvmlDeviceGetGraphicsRunningProcesses_v3")?;
            let driver_version: DriverVerFn = sym(lib, c"nvmlSystemGetDriverVersion")?;
            let err_str: ErrStrFn = sym(lib, c"nvmlErrorString")?;
            let rc = init();
            if rc != NVML_SUCCESS {
                let msg = CStr::from_ptr(err_str(rc)).to_string_lossy().into_owned();
                return Err(format!("nvmlInit failed: {msg} ({rc})"));
            }
            let mut n: c_uint = 0;
            let rc = count(&mut n);
            if rc != NVML_SUCCESS {
                let msg = CStr::from_ptr(err_str(rc)).to_string_lossy().into_owned();
                shutdown();
                return Err(format!("nvmlDeviceGetCount failed: {msg}"));
            }
            let mut devices = Vec::new();
            for i in 0..n {
                let mut h: *mut c_void = std::ptr::null_mut();
                if handle(i, &mut h) == NVML_SUCCESS && !h.is_null() {
                    devices.push(h);
                }
            }
            Ok(Nvml {
                _lib: library,
                shutdown,
                count,
                handle,
                compute,
                graphics,
                driver_version,
                err_str,
                devices,
                scratch: vec![ProcessInfoV3::default(); 256],
            })
        }
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn driver_version(&self) -> String {
        let mut buf = [0 as c_char; 96];
        // SAFETY: buffer length passed matches.
        let rc = unsafe { (self.driver_version)(buf.as_mut_ptr(), buf.len() as c_uint) };
        if rc != NVML_SUCCESS {
            return String::new();
        }
        // SAFETY: NVML NUL-terminates on success.
        unsafe { CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned() }
    }

    fn err(&self, rc: c_int) -> String {
        // SAFETY: nvmlErrorString returns a static string for any code.
        unsafe {
            CStr::from_ptr((self.err_str)(rc))
                .to_string_lossy()
                .into_owned()
        }
    }

    fn query(
        &mut self,
        f: ProcsFn,
        dev: *mut c_void,
        out: &mut Vec<GpuProc>,
    ) -> Result<(), String> {
        loop {
            let mut n = self.scratch.len() as c_uint;
            // SAFETY: scratch has n entries of the correct repr(C) layout.
            let rc = unsafe { f(dev, &mut n, self.scratch.as_mut_ptr()) };
            if rc == NVML_ERROR_INSUFFICIENT_SIZE {
                let want = (n as usize).max(self.scratch.len() * 2).min(8192);
                if want <= self.scratch.len() {
                    return Err("NVML process list too large".into());
                }
                self.scratch.resize(want, ProcessInfoV3::default());
                continue;
            }
            if rc != NVML_SUCCESS {
                return Err(self.err(rc));
            }
            for e in &self.scratch[..(n as usize).min(self.scratch.len())] {
                if e.used_gpu_memory == NVML_VALUE_NOT_AVAILABLE {
                    return Err("NVML per-process memory usage is unavailable".into());
                }
                let bytes = e.used_gpu_memory;
                if e.pid == 0 || bytes > (1u64 << 44) {
                    return Err("implausible NVML process entry (possible ABI mismatch)".into());
                }
                out.push(GpuProc { pid: e.pid, bytes });
            }
            return Ok(());
        }
    }

    /// Per-process GPU memory across all devices and both compute and graphics lists, de-duplicated
    /// by pid (max of the two lists per device, summed across devices).
    pub fn processes(&mut self, out: &mut Vec<GpuProc>) -> Result<(), String> {
        out.clear();
        if self.devices.is_empty() {
            return Err("NVML reports no accessible devices".into());
        }
        let devices = self.devices.clone();
        let mut tmp_c: Vec<GpuProc> = Vec::with_capacity(64);
        let mut tmp_g: Vec<GpuProc> = Vec::with_capacity(16);
        for dev in devices {
            tmp_c.clear();
            tmp_g.clear();
            self.query(self.compute, dev, &mut tmp_c)?;
            // NOT_SUPPORTED is normal on headless systems; other errors invalidate the snapshot.
            if let Err(e) = self.query(self.graphics, dev, &mut tmp_g) {
                if e != self.err(3) {
                    return Err(e);
                } // NVML_ERROR_NOT_SUPPORTED
            }
            for g in &tmp_g {
                match tmp_c.iter_mut().find(|c| c.pid == g.pid) {
                    Some(c) => c.bytes = c.bytes.max(g.bytes),
                    None => tmp_c.push(*g),
                }
            }
            for c in &tmp_c {
                match out.iter_mut().find(|o| o.pid == c.pid) {
                    Some(o) => o.bytes = o.bytes.saturating_add(c.bytes),
                    None => out.push(*c),
                }
            }
        }
        Ok(())
    }

    /// Re-enumerate devices (after driver reload).
    pub fn refresh_devices(&mut self) {
        let mut n: c_uint = 0;
        // SAFETY: valid out pointer.
        if unsafe { (self.count)(&mut n) } != NVML_SUCCESS {
            return;
        }
        self.devices.clear();
        for i in 0..n {
            let mut h: *mut c_void = std::ptr::null_mut();
            // SAFETY: valid out pointer.
            if unsafe { (self.handle)(i, &mut h) } == NVML_SUCCESS && !h.is_null() {
                self.devices.push(h);
            }
        }
    }
}

impl Drop for Nvml {
    fn drop(&mut self) {
        // SAFETY: shutdown then close the library we opened.
        unsafe {
            (self.shutdown)();
        }
    }
}

/// Driver major version from /proc/driver/nvidia/version (e.g. 580). None if unavailable.
pub fn driver_major_from_proc() -> Option<u32> {
    let t = std::fs::read_to_string("/proc/driver/nvidia/version").ok()?;
    for tok in t.split_whitespace() {
        if let Some((maj, rest)) = tok.split_once('.') {
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                if let Ok(m) = maj.parse::<u32>() {
                    if (300..2000).contains(&m) {
                        return Some(m);
                    }
                }
            }
        }
    }
    None
}

pub fn driver_version_from_proc() -> Option<String> {
    let t = std::fs::read_to_string("/proc/driver/nvidia/version").ok()?;
    t.split_whitespace()
        .find(|tok| {
            tok.split('.').count() == 3 && tok.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_layout() {
        assert_eq!(std::mem::size_of::<ProcessInfoV3>(), 24);
        assert_eq!(std::mem::align_of::<ProcessInfoV3>(), 8);
    }

    #[test]
    fn live_nvml_if_present() {
        match Nvml::load() {
            Ok(mut n) => {
                let mut v = Vec::new();
                n.processes(&mut v).unwrap();
                assert!(n.device_count() >= 1);
                assert!(!n.driver_version().is_empty());
                // on this box Xorg/gnome-shell hold a few MiB each
                for p in &v {
                    assert!(p.bytes < 1 << 44);
                }
            }
            Err(e) => eprintln!("NVML not available in test environment: {e}"),
        }
    }

    #[test]
    fn driver_major_parse() {
        if let Some(m) = driver_major_from_proc() {
            assert!(m >= 500);
        }
    }
}
