#![no_std]
#![no_main]

use redbpf_macros::program;

pub mod kernel;
pub mod user;

program!(0xFFFFFFFE, "GPL");
