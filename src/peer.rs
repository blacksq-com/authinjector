//! Caller identity, taken from the kernel.
//!
//! 🔴 IDENTITY IS NEVER THE CALLER'S CLAIM. `SO_PEERCRED` reports the uid of
//! the process on the other end of the Unix socket, as recorded by the kernel
//! at connect time. A caller can write any header it likes; it cannot forge
//! this. Nothing in this program reads an identity from a header, a query
//! parameter or a body field, and nothing ever should.
//!
//! Filesystem permission on the socket is the coarse gate: who may connect at
//! all. This is the fine gate: which of those callers may use which upstream.
//! Two processes in the same group are distinct principals.
//!
//! `std::os::unix::net::UnixStream::peer_cred()` would be the tidy way to do
//! this, but it is still unstable (rust-lang#42839), so the getsockopt is made
//! directly rather than pinning the build to a nightly toolchain.

use std::io;
use std::os::fd::AsRawFd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    pub pid: i32,
    /// Resolved username, or `uid:NNNN` when the uid has no passwd entry.
    /// Policy `callers[]` is matched against this.
    pub name: String,
}

/// Read the peer credentials of a connected Unix socket.
///
/// Safe wrapper: the only `unsafe` is the getsockopt itself, writing into a
/// stack-allocated `ucred` whose size is passed by value. Nothing is parsed
/// from the caller.
pub fn caller_of<F: AsRawFd>(sock: &F) -> io::Result<Caller> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Caller { uid: cred.uid, pid: cred.pid, name: username_for_uid(cred.uid) })
}

/// Map a uid to a username via `/etc/passwd`.
///
/// A plain file read rather than a libc `getpwuid` binding: `getpwuid` pulls in
/// NSS, which defeats a fully static musl build. The fallback form `uid:1001`
/// is stable and usable in policy, so an unresolvable uid degrades to
/// "identified but not named" rather than to "unidentified".
pub fn username_for_uid(uid: u32) -> String {
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            // name:x:uid:gid:gecos:home:shell
            let mut f = line.split(':');
            let name = f.next().unwrap_or("");
            let _x = f.next();
            if let Some(u) = f.next() {
                if u.parse::<u32>().ok() == Some(uid) && !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    format!("uid:{uid}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn unknown_uid_degrades_to_a_stable_usable_form() {
        let n = username_for_uid(4_294_967_294);
        assert_eq!(n, "uid:4294967294");
    }

    #[test]
    fn root_resolves_on_any_normal_system() {
        assert_eq!(username_for_uid(0), "root");
    }

    #[test]
    fn peer_cred_reports_this_process_over_a_socketpair() {
        // A socketpair's far end is this same process, so the kernel must
        // report our own uid and pid. Proves the getsockopt is wired correctly
        // without needing a running broker.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let c = caller_of(&a).expect("peer creds");
        assert_eq!(c.uid, unsafe { libc::getuid() });
        assert_eq!(c.pid, std::process::id() as i32);
        assert!(!c.name.is_empty());
    }
}
