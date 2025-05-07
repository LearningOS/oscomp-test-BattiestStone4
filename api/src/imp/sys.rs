use core::ffi::c_char;

use axerrno::LinuxResult;
use linux_raw_sys::{
    system::__IncompleteArrayField,
    system::{new_utsname, sysinfo},
};

use crate::ptr::UserPtr;

pub fn sys_getuid() -> LinuxResult<isize> {
    Ok(0)
}

pub fn sys_geteuid() -> LinuxResult<isize> {
    Ok(1)
}

pub fn sys_getgid() -> LinuxResult<isize> {
    Ok(0)
}

pub fn sys_getegid() -> LinuxResult<isize> {
    Ok(1)
}

const fn pad_str(info: &str) -> [c_char; 65] {
    let mut data: [c_char; 65] = [0; 65];
    // this needs #![feature(const_copy_from_slice)]
    // data[..info.len()].copy_from_slice(info.as_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(info.as_ptr().cast(), data.as_mut_ptr(), info.len());
    }
    data
}

const UTSNAME: new_utsname = new_utsname {
    sysname: pad_str("Starry"),
    nodename: pad_str("Starry - machine[0]"),
    release: pad_str("10.0.0"),
    version: pad_str("10.0.0"),
    machine: pad_str("10.0.0"),
    domainname: pad_str("https://github.com/oscomp/starry-next"),
};

pub fn sys_uname(name: UserPtr<new_utsname>) -> LinuxResult<isize> {
    *name.get_as_mut()? = UTSNAME;
    Ok(0)
}

const SYSINFO: sysinfo = sysinfo {
    uptime: 0,
    loads: [0, 0, 0],
    totalram: 0,
    freeram: 0,
    sharedram: 0,
    bufferram: 0,
    totalswap: 0,
    freeswap: 0,
    procs: 0,
    totalhigh: 0,
    freehigh: 0,
    mem_unit: 0,
    pad: 0,
    _f: __IncompleteArrayField::new(),
};

pub fn sys_sysinfo(info: UserPtr<sysinfo>) -> LinuxResult<isize> {
    *info.get_as_mut()? = SYSINFO;
    Ok(0)
}
