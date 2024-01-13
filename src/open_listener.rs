/**
 * We listen for open calls and try to deduce actual TLS library usage from there.
 * This runs from a separate thread that does a couple of things:
 * - It tracks process ids and their mount namespace
 * - It tracks mount namespaces and their root filesystems
 * - It tracks the top level filesystems
 * From these three items, it can quickly figure out what the "real" pathname in
 * a library open call is.
 *
 * For now, we keep the probe etc simple by sending all messages through the
 * same channel from eBPF to user mode. This means that the event listener gets the
 * open messages, not this code; we setup a channel between the two to forward
 * these messages.
 */
use redbpf::Module;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;

pub struct OpenMsg {
    pub lib_name: String,
    pub pid: u32,
}

pub fn start_open_listener(mut module: Module) -> Sender<OpenMsg> {
    probe_kernel(&mut module);

    // 1024 messages allows plenty of backlogs, which we'd expect if things
    // start up.
    let (tx, rx) = mpsc::channel::<OpenMsg>(1024);
    tokio::spawn(async move {
        run_open_listener(rx, module).await;
    });
    tx
}

#[allow(unused_must_use)]
async fn run_open_listener(mut rx: Receiver<OpenMsg>, mut module: Module) {
    let mut mount_ns_by_pid = HashMap::<u32, String>::new();
    let mut root_by_ns = HashMap::<String, String>::new();
    let mut system_mounts = HashMap::<String, String>::new();
    let mut monitored_libs = HashSet::<String>::new();
    let mut last_cleanup = Instant::now();

    while let Some(cmd) = rx.recv().await {
        if last_cleanup.elapsed().as_secs() > 60 {
            // Every minute, we do a cleanup of our maps so we don't grow memory endlessly.
            // Cleanup code is inline to save us from having a function with a lot of arguments.
            // And yes, if no new libraries are opened we are not called. It's not _that_ much
            // memory we are keeping; if we are on an active system w.r.t. executing processes,
            // we will get called, and if we are on a system that just starts a service and
            // that's it, we don't really need to be called.

            // cleanout non existent pids
            let mut pre_len = mount_ns_by_pid.len();
            mount_ns_by_pid.retain(|&k, _| Path::new(format!("/proc/{}", k).as_str()).is_dir());
            let mut post_len = mount_ns_by_pid.len();
            println!(
                "Cleanup: Cleaned {} pids, remaining {}, capacity {}",
                pre_len - post_len,
                post_len,
                mount_ns_by_pid.capacity()
            );

            // cleanout unused namespaces. Note that the
            // hashset is probably overkill, as machines typically
            // don't have tons of active namespaces.
            pre_len = root_by_ns.len();
            let mut used_ns = HashSet::new();
            for ns in mount_ns_by_pid.values() {
                used_ns.insert(ns);
            }
            root_by_ns.retain(|k, _| used_ns.contains(k));
            post_len = root_by_ns.len();
            println!(
                "Cleanup: Cleaned {} namespaces, remaining {}, capacity {}",
                pre_len - post_len,
                post_len,
                root_by_ns.capacity()
            );

            println!("Cleanup: monitored libs count is {}, capacity {}", monitored_libs.len(), monitored_libs.capacity());

            // if we remove namespaces, we maybe also want to remove monitored libraries. What
            // would be the rule for ending the monitoring of libraries?

            last_cleanup = Instant::now();
        }

        // Options everywhere. While for an existing pid, all this stuff should exist, it may
        // very well be the case that it exited before we get here.
        let maybe_ns = match mount_ns_by_pid.get(&cmd.pid) {
            Some(ns) => Some(ns),
            None => {
                if let Some(mount_ns) = get_mount_ns_by_pid(cmd.pid) {
                    mount_ns_by_pid.insert(cmd.pid, mount_ns);
                    mount_ns_by_pid.get(&cmd.pid)
                } else {
                    None
                }
            }
        };

        let maybe_root = if let Some(ns) = maybe_ns {
            match root_by_ns.get(ns) {
                Some(root) => Some(root),
                None => {
                    if let Some(root) = get_root_by_pid(cmd.pid) {
                        root_by_ns.insert(ns.clone(), root);
                        root_by_ns.get(ns)
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        };

        let maybe_real_root = if let Some(root) = maybe_root {
            match system_mounts.get(root) {
                Some(real) => Some(real),
                None => {
                    // Not found means we gotta refresh the map
                    system_mounts = get_system_mounts();
                    system_mounts.get(root)
                }
            }
        } else {
            None
        };

        // Combine library path and root path, check in watched libs
        // If not available, start probing.
        let maybe_real_path = if let Some(real_root) = maybe_real_root {
            match real_root.as_str() {
                "/" => Some(cmd.lib_name),
                path => {
                    let mut rp = String::from(path);
                    rp.extend(cmd.lib_name.chars());
                    Some(rp)
                }
            }
        } else {
            None
        };

        if let Some(real_path) = maybe_real_path {
            if monitored_libs.insert(real_path.clone()) {
                // new entry, start monitoring
                probe_lib(real_path.as_str(), &mut module);
            }
        }
    }
}

fn probe_lib(lib: &str, module: &mut redbpf::Module) -> redbpf::Result<()> {
    println!("Attaching to {}.", lib);
    // Note that this may fail - we have multiple library types and may insert the
    // wrong probe for that library.
    for probe in module.uprobes_mut() {
        let res = probe.attach_uprobe(Some(probe.name().as_str()), 0, lib, None);
        if res.is_err() {
            println!(
                "warning: could not attach uprobe {} to {}: {:?}",
                probe.name(),
                lib,
                res
            );
        }
    }
    Ok(())
}

fn probe_kernel(module: &mut Module) {
    // This should not fail, if it does, panicking is fine.
    for probe in module.kprobes_mut() {
        // As luck would have it, openat2() got introduced in the same kernel version
        // as read_use_str() which pins the oldest kernel we can use. So we can safely
        // assume it to be available.
        probe
            .attach_kprobe("do_sys_openat2", 0)
            .expect("Cannot attach openat2 probe");
    }
}

fn get_mount_ns_by_pid(pid: u32) -> Option<String> {
    let file = format!("/proc/{}/ns/mnt", pid);
    if let Ok(pb) = fs::read_link(file) {
        let str = pb.to_str()?;
        Some(String::from(str))
    } else {
        None
    }
}

fn get_root_by_pid(pid: u32) -> Option<String> {
    let mounts = format!("/proc/{}/mounts", pid);
    let contents = fs::read_to_string(mounts).ok()?;
    // first line with " / "
    let root_fs_line = contents
        .lines()
        .filter(|line| line.contains(" / "))
        .next()
        .unwrap();
    let (key, _) = key_val_from_line(root_fs_line);
    Some(key)
}

fn get_system_mounts() -> HashMap<String, String> {
    // If we cannot open /proc/mounts, crashing is fine.
    let contents = fs::read_to_string("/proc/mounts").expect("Could not read mounts file");
    contents
        .lines()
        .map(|line| key_val_from_line(line))
        .collect()
}

fn key_val_from_line(line: &str) -> (String, String) {
    // Format is <device> <mount_point> <type> <opts> 0 0
    let split: Vec<&str> = line.split_ascii_whitespace().collect();
    let dev = String::from(split[0]);
    let typ = String::from(split[2]);
    let opt = String::from(split[3]);
    let key = format!("{}:{}:{}", dev, typ, opt);
    (key, String::from(split[1]))
}
