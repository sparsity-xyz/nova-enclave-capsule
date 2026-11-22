use anyhow::{Context, Result, anyhow, ensure};
use log::debug;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::{Gid, Group, Pid, Uid, User, getgrouplist, setgroups, setresgid, setresuid};
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use tokio::task::JoinHandle;

#[derive(Debug, PartialEq, Eq)]
pub struct Credentials {
    pub uid: Uid,
    pub gid: Gid,
    groups: Vec<Gid>,
}

/// Distinguish an account name from a numeric ID without accepting the setresuid -1 sentinel.
fn numeric_id(value: &str) -> Result<Option<u32>> {
    ensure!(
        !value.is_empty() && !value.contains(':'),
        "invalid image USER"
    );
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let id: u32 = value.parse().context("image USER ID out of range")?;
    ensure!(id < u32::MAX, "reserved image USER ID");
    Ok(Some(id))
}

impl Credentials {
    pub fn from_image_user(spec: Option<&str>) -> Result<Self> {
        let Some(spec) = spec.filter(|s| !s.is_empty()) else {
            return Ok(Self {
                uid: Uid::from_raw(0),
                gid: Gid::from_raw(0),
                groups: vec![],
            });
        };
        let (user, group) = spec.split_once(':').unwrap_or((spec, ""));
        let explicit_group = !group.is_empty();
        let (uid, account) = match numeric_id(user)? {
            Some(id) => {
                let uid = Uid::from_raw(id);
                // Numeric USER uid:gid works in scratch images without account files.
                let account = if explicit_group {
                    None
                } else {
                    User::from_uid(uid)?
                };
                (uid, account)
            }
            None => {
                let account = User::from_name(user)?
                    .with_context(|| format!("unknown image user {user:?}"))?;
                (account.uid, Some(account))
            }
        };
        let (gid, groups) = if explicit_group {
            let gid = match numeric_id(group)? {
                Some(id) => Gid::from_raw(id),
                None => {
                    Group::from_name(group)?
                        .with_context(|| format!("unknown image group {group:?}"))?
                        .gid
                }
            };
            (gid, vec![])
        } else if let Some(account) = account {
            let name = CString::new(account.name)?;
            let mut groups = getgrouplist(&name, account.gid)?;
            groups.retain(|gid| *gid != account.gid);
            (account.gid, groups)
        } else {
            (Gid::from_raw(0), vec![])
        };
        ensure!(
            uid.as_raw() < u32::MAX && gid.as_raw() < u32::MAX,
            "reserved account ID"
        );
        Ok(Self { uid, gid, groups })
    }

    fn apply_to_child(self, cmd: &mut Command) {
        // SAFETY: lookup and allocation finish in the parent. Only credential syscalls
        // run between fork and exec; a failure aborts spawn before app code can execute.
        unsafe {
            cmd.pre_exec(move || {
                setgroups(&self.groups)?;
                setresgid(self.gid, self.gid, self.gid)?;
                if !self.uid.is_root() {
                    let on: nix::libc::c_ulong = 1;
                    let unused: nix::libc::c_ulong = 0;
                    let rc = nix::libc::prctl(
                        nix::libc::PR_SET_NO_NEW_PRIVS,
                        on,
                        unused,
                        unused,
                        unused,
                    );
                    if rc == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                setresuid(self.uid, self.uid, self.uid)?;
                Ok(())
            });
        }
    }
}

pub enum ExitStatus {
    Exited(i32),
    Signaled(Signal),
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ExitStatus::Exited(code) => write!(f, "exited with {}", code),
            ExitStatus::Signaled(sig) => write!(f, "terminated by {}", sig),
        }
    }
}

// runs the child and reaps all of its children as well
pub fn run_child(
    argv: &[OsString],
    creds: Credentials,
    work_dir: Option<PathBuf>,
) -> Result<ExitStatus> {
    // Don't use tokio::process::Command because it wants to reap the process.
    // However we need to run waitpid() ourselves to reap the zombies and it'll
    // end up picking up the spawned child as well.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).process_group(0);
    creds.apply_to_child(&mut cmd);

    if let Some(dir) = work_dir {
        cmd.current_dir(dir);
    }

    let child = cmd.spawn()?;

    debug!("Child process started");
    let child_pid = Pid::from_raw(child.id() as i32);

    reap(child_pid)
}

// runs the child and reaps all of its children as well
pub fn start_child(
    argv: Vec<OsString>,
    creds: Credentials,
    work_dir: Option<PathBuf>,
) -> JoinHandle<Result<ExitStatus>> {
    tokio::task::spawn_blocking(move || run_child(&argv, creds, work_dir))
}

// Reap processes until a process with sentinel pid exits.
// Returns the exit status for the sentinel process
fn reap(sentinel: Pid) -> Result<ExitStatus> {
    let flags = WaitPidFlag::empty();

    loop {
        let wait_status = nix::sys::wait::waitpid(None, Some(flags))
            .map_err(|e| anyhow!("waitpid failed: {}", e))?;

        match wait_status {
            WaitStatus::Exited(pid, status) => {
                debug!("Zombie with PID {} reaped", pid);
                if pid == sentinel {
                    // our child is done, exit
                    return Ok(ExitStatus::Exited(status));
                }
            }
            WaitStatus::Signaled(pid, sig, _) => {
                debug!("Zombie with PID {} reaped", pid);
                if pid == sentinel {
                    // our child crashed by signal, exit
                    return Ok(ExitStatus::Signaled(sig));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_user_resolution() {
        let legacy = Credentials::from_image_user(None).unwrap();
        assert!(legacy.uid.is_root());
        assert!(legacy.groups.is_empty());
        assert_eq!(legacy, Credentials::from_image_user(Some("")).unwrap());
        assert_eq!(
            legacy,
            Credentials::from_image_user(Some("root:root")).unwrap()
        );
        let numeric = Credentials::from_image_user(Some("1000:1001")).unwrap();
        assert_eq!((numeric.uid.as_raw(), numeric.gid.as_raw()), (1000, 1001));
        assert!(numeric.groups.is_empty());
        let by_name = Credentials::from_image_user(Some("root")).unwrap();
        assert_eq!(by_name, Credentials::from_image_user(Some("0")).unwrap());
        for invalid in [
            "no-such-capsule-test-user",
            "1000:no-such-capsule-test-group",
            ":1000",
            "1:2:3",
            "4294967295:0",
            "0:4294967296",
        ] {
            assert!(
                Credentials::from_image_user(Some(invalid)).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn child_drops_privileges_or_fails_before_exec() {
        let parent_uid = Uid::effective();
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-ec",
            r#"test "$(id -u):$(id -g):$(id -G)" = "1000:1001:1001"
            grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
            grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status"#,
        ]);
        Credentials::from_image_user(Some("1000:1001"))
            .unwrap()
            .apply_to_child(&mut cmd);
        match cmd.status() {
            Ok(status) => assert!(status.success()),
            Err(error) if !parent_uid.is_root() => {
                assert_eq!(error.raw_os_error(), Some(nix::libc::EPERM));
            }
            Err(error) => panic!("failed to launch child: {error}"),
        }
        assert_eq!(Uid::effective(), parent_uid);
    }
}
