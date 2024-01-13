use redbpf::load::Loader;
use rlimit::Resource;
use std::env;
use std::net::UdpSocket;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use uname::uname;

mod open_listener;
use crate::open_listener::start_open_listener;
mod event_listener;
use crate::event_listener::start_event_listener;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/tls_mon/tls_mon.elf"
    ))
}

#[allow(unused_must_use)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    Resource::MEMLOCK
        .set(u64::MAX, u64::MAX)
        .expect("could not increase locked memory limit");

    // 5.5 introduced read_user_str which is the newest feature we use.
    // https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md has an overview
    // of everything.
    let kernel_version = kernel_version();
    if kernel_version[0] < 5 ||
        (kernel_version[0] == 5 && kernel_version[1] < 5) {
       panic!("The eBPF plugin won't work on kernels before version 5.5.")
    }

    let loaded = Loader::load(probe_code()).expect("error on Loader::load");
    let tx = start_open_listener(loaded.module);

    let host = env::var("METRIST_ORCHESTRATOR_ENDPOINT").unwrap_or("127.0.0.1:51712".to_string());
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Could not bind socket");
    sock.connect(host).expect("connect() call failed");

    start_event_listener(loaded.events, sock, tx).await;

    println!("Exiting.");
}

fn kernel_version() -> Vec<u32> {
    let kernel_info = uname().unwrap();
    println!("System info = {:?}", kernel_info);
    let kernel_version: Vec<u32> =
        kernel_info.release
                   .split_terminator(".")
                   .take(2)
                   .map(|str|
                        str.parse::<u32>().expect("Unexpected kernel version specifier"))
                   .collect();

    if kernel_version.len() < 2 {
        panic!("Could not parse kernel version from {:?}", kernel_info)
    }

    kernel_version
}
