//! Thin, dependency-free readers for /proc, cgroup v2 and the NVIDIA libraries.

pub mod cgroup;
pub mod cuda;
pub mod meminfo;
pub mod nvml;
pub mod procfs;
pub mod psi;

/// Own a dlopen reference, including while loading fallible symbol tables.
pub(crate) struct Library(pub *mut std::ffi::c_void);

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: this handle owns a successful dlopen reference.
        unsafe {
            libc::dlclose(self.0);
        }
    }
}
