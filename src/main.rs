#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate axlog;
extern crate alloc;

mod syscall;

use alloc::vec::Vec;
use starry_core::entry::run_user_app;


#[unsafe(no_mangle)]
fn main() {
    ax_println!("#### OS COMP TEST GROUP START basic-glibc ####");
    ax_println!("#### OS COMP TEST GROUP START basic-musl ####");
    let testcases = option_env!("AX_MUSL_BASIC_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    for testcase in testcases {
        let args = testcase
            .split_ascii_whitespace()
            .map(Into::into)
            .collect::<Vec<_>>();

        let exit_code = run_user_app(&args, &[]);
        info!("User task {} exited with code: {:?}", testcase, exit_code);
    }
    ax_println!("#### OS COMP TEST GROUP END basic-musl ####");
    ax_println!("#### OS COMP TEST GROUP END basic-glibc ####");

    ax_println!("#### OS COMP TEST GROUP START libctest-glibc ####");
    ax_println!("#### OS COMP TEST GROUP START libctest-musl ####");
    let testcases = option_env!("AX_MUSL_LIBCTEST_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    for testcase in testcases {
        let args = testcase
            .split_ascii_whitespace()
            .map(Into::into)
            .collect::<Vec<_>>();

        let exit_code = run_user_app(&args, &[]);
        info!("User task {} exited with code: {:?}", testcase, exit_code);
    }
    ax_println!("#### OS COMP TEST GROUP END libctest-musl ####");
    ax_println!("#### OS COMP TEST GROUP END libctest-glibc ####");
}
