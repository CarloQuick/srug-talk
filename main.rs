use anyhow::{Context, Result};
use std::{
    env,
    ffi::CString,
    fs,
    path::{Path, PathBuf},
};

use nix::{
    mount::{MsFlags, mount},
    sched::{CloneFlags, unshare},
    sys::wait::waitpid,
    unistd::{ForkResult, chroot, execvp, fork, getcwd, geteuid, getpid},
};

fn get_proc_info() -> Result<()> {
    eprintln!(
        "euid [{}] pid [{}] cwd [{:?}]",
        geteuid(),
        getpid(),
        getcwd().context("Failed to get the cwd.")?
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        anyhow::bail!("Usage: <cmd> [args...]\nExample: ls -la");
    }
    let cmd = &args[1];
    let argv: Vec<CString> = args[1..]
        .iter()
        .map(|s| CString::new(s.as_str()).context("Not a valid CString arg."))
        .collect::<Result<_>>()?;

    let rootfs = PathBuf::from("/home/cquick/talks/rootfs");
    let container_dir = PathBuf::from("/home/cquick/talks/container");

    // Go rootless
    let host_uid = nix::unistd::getuid();
    let host_gid = nix::unistd::getgid();
    let uid_map = format!("0 {} 1", host_uid);
    let gid_map = format!("0 {} 1", host_gid);
    unshare(CloneFlags::CLONE_NEWUSER).context("Failed to create user namespace")?;
    std::fs::write("/proc/self/uid_map", uid_map).context("Failed to write to uid")?;
    let setgroups_path = PathBuf::from("/proc").join("self").join("setgroups");
    std::fs::write(setgroups_path, "deny").context("Failed to write to gid setgroup")?;
    std::fs::write("/proc/self/gid_map", gid_map).context("Failed to write to gid")?;

    unshare(CloneFlags::CLONE_NEWUTS).context("Failed to create uts namespace")?;
    unshare(CloneFlags::CLONE_NEWPID).context("Failed to create a PID namespace")?;
    //** Create mount namespace (isolates your filesystem operations) **//
    unshare(CloneFlags::CLONE_NEWNS).context("Failed to create a mounted namespace")?;
    if !Path::new(&container_dir).exists() {
        fs::create_dir_all(&container_dir).context("Failed to create path")?;
    }
    //** Mount/copy your container filesystem into that directory **//
    let source_dir = &rootfs;
    let source = Some(source_dir);
    let target = &container_dir;
    let fstype = None::<&str>;
    let flags = MsFlags::MS_BIND;
    let data = None::<&str>;
    mount(source, target, fstype, flags, data).context("Failed to Mount Filesystem")?;

    // Create a child process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            waitpid(child, None)
                .context("Something went wrong waiting for the child's signal to change.")?;
        }
        Ok(ForkResult::Child) => {
            chroot(&container_dir).context("chroot failed")?;
            std::env::set_current_dir("/").context("Couldn't change current working directory.")?;
            fs::create_dir_all("/proc")
                .context("Failed to create /proc before mounting the process' proc")?;
            mount(
                Some("proc"),
                "/proc",
                Some("proc"),
                MsFlags::empty(),
                None::<&[u8]>,
            )
            .context("Failed to Mount /proc")?;
            get_proc_info().context("Failed to get process information.")?;
            execvp(
                &CString::new(cmd.to_owned()).context("Not a valid CString: cmd")?,
                &argv,
            )
            .context("Failed to replace current process image [exec]")?;
            unreachable!("execvp should not return on success");
        }
        Err(e) => Err(e).context("Fork failed")?,
    }
    Ok(())
}
