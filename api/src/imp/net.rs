use core::ffi::{c_char, c_void};

use arceos_posix_api::{self as api, 
    ctypes::{
        sockaddr, 
        socklen_t,
        size_t
    }
};
use axerrno::LinuxResult;

pub fn sys_socket(domain: i32, socktype: i32, protocol: i32) -> LinuxResult<isize> {
    Ok(api::sys_socket(domain, socktype, protocol) as isize)
}

pub fn sys_bind(socket_fd: i32,
    socket_addr: *const sockaddr,
    addrlen: socklen_t
) -> LinuxResult<isize> {
    debug!(
        "sys_bind <= {:?}", unsafe { *(socket_addr as *const sockaddr) }
    );
    Ok(api::sys_bind(socket_fd, socket_addr, addrlen) as isize)
}

pub fn sys_getsockname(sock_fd: i32,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t
) -> LinuxResult<isize> {
    unsafe { Ok(api::sys_getsockname(sock_fd, addr, addrlen) as isize) }
}

pub fn sys_setsockopt(sock_fd: i32,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: socklen_t
) -> LinuxResult<isize> {
    Ok(api::sys_setsockopt(sock_fd, level, optname, optval as _, optlen) as isize)
}

pub fn sys_sendto(socket_fd: i32,
    buf_ptr: *const c_void,
    len: size_t,
    flag: i32,
    socket_addr: *const sockaddr,
    addrlen: socklen_t
) -> LinuxResult<isize> {
    debug!(
        "sys_sendto <= {:?}", unsafe { *(socket_addr as *const sockaddr) }
    );
    Ok(api::sys_sendto(socket_fd, buf_ptr, len, flag, socket_addr, addrlen) as isize)
}

pub fn sys_recvfrom(socket_fd: i32,
    buf_ptr: *mut c_void,
    len: size_t,
    flag: i32,
    socket_addr: *mut sockaddr,
    addrlen: *mut socklen_t
) -> LinuxResult<isize> {
    unsafe { Ok(api::sys_recvfrom(socket_fd, buf_ptr, len, flag, socket_addr, addrlen) as isize) }
}

pub fn sys_shutdown(socket_fd: i32, how: i32) -> LinuxResult<isize> {
    Ok(api::sys_shutdown(socket_fd, how) as isize)
}

pub fn sys_listen(socket_fd: i32, backlog: i32) -> LinuxResult<isize> {
    Ok(api::sys_listen(socket_fd, backlog) as isize)
}

pub fn sys_accept(socket_fd: i32,
    socket_addr: *mut sockaddr,
    addrlen: *mut socklen_t
) -> LinuxResult<isize> {
    unsafe { Ok(api::sys_accept(socket_fd, socket_addr, addrlen) as isize) }
}

pub fn sys_connect(socket_fd: i32,
    socket_addr: *const sockaddr,
    addrlen: socklen_t
) -> LinuxResult<isize> {
    debug!(
        "sys_connect <= {:?}", unsafe { *(socket_addr as *const sockaddr) }
    );
    Ok(api::sys_connect(socket_fd, socket_addr, addrlen) as isize)
}