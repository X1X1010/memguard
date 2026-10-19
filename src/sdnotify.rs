//! Hand-written sd_notify (no libsystemd). Non-blocking datagrams; failures are ignored.

use std::os::unix::io::RawFd;

pub struct SdNotify {
    fd: RawFd,
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
}

impl SdNotify {
    /// Returns None when NOTIFY_SOCKET is unset (not started by systemd).
    pub fn from_env() -> Option<SdNotify> {
        let path = std::env::var("NOTIFY_SOCKET").ok()?;
        let bytes = path.as_bytes();
        // SAFETY: zeroed sockaddr_un is a valid starting point; we bound the copy to sun_path.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if bytes.is_empty() || bytes.len() >= addr.sun_path.len() {
            return None;
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        if bytes[0] == b'@' {
            addr.sun_path[0] = 0; // abstract namespace
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len()) as libc::socklen_t;
        // SAFETY: plain socket creation.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return None;
        }
        Some(SdNotify { fd, addr, len })
    }

    pub fn send(&self, msg: &str) {
        // SAFETY: valid buffer and sockaddr; MSG_NOSIGNAL avoids SIGPIPE.
        unsafe {
            libc::sendto(
                self.fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                &self.addr as *const libc::sockaddr_un as *const libc::sockaddr,
                self.len,
            );
        }
    }

    pub fn ready(&self) {
        self.send("READY=1\n");
    }

    pub fn watchdog(&self) {
        self.send("WATCHDOG=1\n");
    }

    pub fn stopping(&self) {
        self.send("STOPPING=1\n");
    }

    pub fn status(&self, s: &str) {
        let clean: String = s.chars().filter(|c| *c != '\n').take(200).collect();
        self.send(&format!("STATUS={clean}\n"));
    }
}

impl Drop for SdNotify {
    fn drop(&mut self) {
        // SAFETY: fd owned here.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// WATCHDOG_USEC from the environment, if systemd asked for keepalives.
pub fn watchdog_usec() -> Option<u64> {
    std::env::var("WATCHDOG_USEC").ok()?.parse().ok()
}
