use core::{
    ffi::{c_char, c_int, c_uint},
    panic,
};

use crate::{
    fd::{Directory, FD_TABLE, File, FileLike, add_file_like, close_file_like, get_file_like},
    path::handle_file_path,
};
use alloc::{borrow::ToOwned, string::String};
use axerrno::{AxError, LinuxError, LinuxResult};
use axfs::{CURRENT_DIR_PATH, fops::OpenOptions};
use axfs_vfs::VfsNodePerm;
use axio::SeekFrom;
use bitflags::bitflags;
use linux_raw_sys::{
    general::{
        __kernel_mode_t, __kernel_off_t, AT_FDCWD, F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL,
        F_SETFL, FD_CLOEXEC, O_APPEND, O_CREAT, O_DIRECTORY, O_NONBLOCK, O_PATH, O_RDONLY, O_TRUNC,
        O_WRONLY,
    },
};

use crate::ptr::UserConstPtr;

const O_EXEC: u32 = O_PATH;

/// Convert open flags to [`OpenOptions`].
fn flags_to_options(flags: c_int, _mode: __kernel_mode_t) -> OpenOptions {
    let flags = flags as u32;
    let mut options = OpenOptions::new();
    match flags & 0b11 {
        O_RDONLY => options.read(true),
        O_WRONLY => options.write(true),
        _ => {
            options.read(true);
            options.write(true);
        }
    };
    if flags & O_APPEND != 0 {
        options.append(true);
    }
    if flags & O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & O_CREAT != 0 {
        options.create(true);
    }
    if flags & O_EXEC != 0 {
        //options.create_new(true);
        options.execute(true);
    }
    if flags & O_DIRECTORY != 0 {
        options.directory(true);
    }
    options
}

/// Open or create a file.
/// fd: file descriptor
/// filename: file path to be opened or created
/// flags: open flags
/// mode: see man 7 inode
/// return new file descriptor if succeed, or return -1.
pub fn sys_openat(
    dirfd: c_int,
    path: UserConstPtr<c_char>,
    flags: i32,
    mode: __kernel_mode_t,
) -> LinuxResult<isize> {
    let path = path.get_as_str()?;
    let opts = flags_to_options(flags, mode);
    debug!("sys_openat <= {} {} {:?}", dirfd, path, opts);

    let dir = if path.starts_with('/') || dirfd == AT_FDCWD {
        None
    } else {
        Some(Directory::from_fd(dirfd)?)
    };

    if !opts.has_directory() {
        match dir.as_ref().map_or_else(
            || axfs::fops::File::open(path, &opts),
            |dir| dir.inner().open_file_at(path, &opts),
        ) {
            Err(AxError::IsADirectory) => {}
            r => {
                let fd = File::new(r?, path.into()).add_to_fd_table()?;
                return Ok(fd as _);
            }
        }
    }

    let fd = Directory::new(
        dir.map_or_else(
            || axfs::fops::Directory::open_dir(path, &opts),
            |dir| dir.inner().open_dir_at(path, &opts),
        )?,
        path.into(),
    )
    .add_to_fd_table()?;
    Ok(fd as _)
}

/// Open a file by `filename` and insert it into the file descriptor table.
///
/// Return its index in the file table (`fd`). Return `EMFILE` if it already
/// has the maximum number of files open.
pub fn sys_open(
    path: UserConstPtr<c_char>,
    flags: i32,
    mode: __kernel_mode_t,
) -> LinuxResult<isize> {
    sys_openat(AT_FDCWD as _, path, flags, mode)
}

pub fn sys_close(fd: c_int) -> LinuxResult<isize> {
    debug!("sys_close <= {}", fd);
    close_file_like(fd)?;
    Ok(0)
}

fn dup_fd(old_fd: c_int) -> LinuxResult<isize> {
    let f = get_file_like(old_fd)?;
    let new_fd = add_file_like(f)?;
    Ok(new_fd as _)
}

pub fn sys_dup(old_fd: c_int) -> LinuxResult<isize> {
    debug!("sys_dup <= {}", old_fd);
    dup_fd(old_fd)
}

pub fn sys_dup2(old_fd: c_int, new_fd: c_int) -> LinuxResult<isize> {
    debug!("sys_dup2 <= old_fd: {}, new_fd: {}", old_fd, new_fd);
    let mut fd_table = FD_TABLE.write();
    let f = fd_table
        .get(old_fd as _)
        .cloned()
        .ok_or(LinuxError::EBADF)?;

    if old_fd != new_fd {
        fd_table.remove(new_fd as _);
        fd_table
            .add_at(new_fd as _, f)
            .unwrap_or_else(|_| panic!("new_fd should be valid"));
    }

    Ok(new_fd as _)
}

pub fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> LinuxResult<isize> {
    debug!("sys_fcntl <= fd: {} cmd: {} arg: {}", fd, cmd, arg);

    match cmd as u32 {
        F_DUPFD => dup_fd(fd),
        F_DUPFD_CLOEXEC => {
            // TODO: Change fd flags
            dup_fd(fd)
        }
        F_SETFL => {
            if fd == 0 || fd == 1 || fd == 2 {
                return Ok(0);
            }
            get_file_like(fd)?.set_nonblocking(arg & (O_NONBLOCK as usize) > 0)?;
            Ok(0)
        }
        F_GETFD => {
            warn!("unsupported fcntl parameters: F_GETFD, returning FD_CLOEXEC");
            Ok(FD_CLOEXEC as _)
        }
        F_GETFL => {
            warn!("unsupported fcntl parameters: F_GETFL, returning O_NONBLOCK");
            Ok(O_NONBLOCK as _)
        }
        _ => {
            warn!("unsupported fcntl parameters: cmd: {}", cmd);
            Ok(0)
        }
    }
}

pub fn sys_lseek(fd: c_int, offset: __kernel_off_t, whence: c_int) -> LinuxResult<isize> {
    debug!("sys_lseek <= {} {} {}", fd, offset, whence);
    let pos = match whence {
        0 => SeekFrom::Start(offset as _),
        1 => SeekFrom::Current(offset as _),
        2 => SeekFrom::End(offset as _),
        _ => return Err(LinuxError::EINVAL),
    };
    let off = File::from_fd(fd)?.inner().seek(pos)?;
    Ok(off as _)
}

bitflags! {
    pub struct AccessModes: u32 {
        const X_OK = 1;
        const W_OK = 2;
        const R_OK = 4;
    }
}

fn resolve_path(dirfd: c_int, path: &str) -> LinuxResult<String> {
    Ok(if path.starts_with('/') {
        path.to_owned()
    } else if dirfd == AT_FDCWD {
        alloc::format!("{}/{}", CURRENT_DIR_PATH.lock(), path)
    } else {
        alloc::format!("{}/{}", Directory::from_fd(dirfd)?.path(), path)
    })
}

pub fn sys_access(path: UserConstPtr<c_char>, mode: u32) -> LinuxResult<isize> {
    sys_faccessat(AT_FDCWD, path, mode, 0)
}

pub fn sys_faccessat(
    dirfd: c_int,
    path: UserConstPtr<c_char>,
    mode: u32,
    _flags: u32,
) -> LinuxResult<isize> {
    // TODO: check flags
    info!(
        "sys_faccessat: dirfd: {}, path: {}, mode:{}",
        dirfd,
        path.get_as_str()?,
        mode
    );
    let modes = AccessModes::from_bits(mode).ok_or(LinuxError::EINVAL)?;
    let mut perms = VfsNodePerm::empty();
    if modes.contains(AccessModes::R_OK) {
        perms.insert(VfsNodePerm::OWNER_READ);
    }
    if modes.contains(AccessModes::W_OK) {
        perms.insert(VfsNodePerm::OWNER_WRITE);
    }
    if modes.contains(AccessModes::X_OK) {
        perms.insert(VfsNodePerm::OWNER_EXEC);
    }

    let path = path.get_as_str()?;
    let path = if path.starts_with("/bin/") {
        "/musl/busybox"
    } else {
        path
    };
    let path = resolve_path(dirfd, path)?;
    let metadata = axfs::api::metadata(&path)?;
    if !metadata.permissions().contains(perms) {
        return Err(LinuxError::EACCES);
    }

    Ok(0)
}

pub fn sys_renameat2(
    old_dirfd: c_int,
    old: UserConstPtr<c_char>,
    new_dirfd: c_int,
    new: UserConstPtr<c_char>,
    _flags: c_uint,
) -> LinuxResult<isize> {
    //TODO: handle with flags
    sys_renameat(old_dirfd, old, new_dirfd, new)
}

pub fn sys_renameat(
    old_dirfd: c_int,
    old: UserConstPtr<c_char>,
    new_dirfd: c_int,
    new: UserConstPtr<c_char>,
) -> LinuxResult<isize> {
    let old_path = handle_file_path(old_dirfd, old.get_as_str()?)?;
    let new_path = handle_file_path(new_dirfd, new.get_as_str()?)?;
    info!("sys_rename <= old: {:?}, new: {:?}", old_path, new_path);
    axfs::api::rename(&old_path, &new_path)?;
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
pub fn sys_rename(old: UserConstPtr<c_char>, new: UserConstPtr<c_char>) -> LinuxResult<isize> {
    sys_renameat(AT_FDCWD, old, AT_FDCWD, new)
}
