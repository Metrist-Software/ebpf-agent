use redbpf_probes::kprobe::prelude::*;
use probes::tls_mon::*;

// static long do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
// open, openat, openat2 all eventually land here.
#[allow(unused_must_use)]
#[kretprobe]
pub fn do_sys_openat2(regs: Registers, parms: [u64; 5]) {
    if regs.rc() as i64 > 0 {
        unsafe {
            let mut event = TMP_EVENT.get_mut(0).unwrap();
            event.kind = Kind::OpenAt;
            event.ts = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
            event.tgid = (pid_tgid >> 32) as u32;

            let filename = parms[1] as *const u8;
            let err_or_len =
                bpf_probe_read_user_str(
                    event.data.as_mut_ptr() as *mut _,
                    event.data.len() as u32,
                    filename as *const _);
            // Invalid addresses seem to happen...
            if err_or_len < 0 && err_or_len != -14 {
                printk!("error %lld on open probe/bpf_probe_read_user_str", err_or_len);
            } else {
                event.len = if err_or_len as usize > BUFSIZE {BUFSIZE} else {err_or_len as usize};
                if !ignore(&event.data, event.len) {
                    TLS_BUF.insert(regs.ctx, &event);
                }
            }
        }
    }
}

// Most executable emit a ton of open calls when starting up. Make sure we
// only pick out the ones for libraries we actually want to trace.
//
// Note that `len` here includes the null terminator.
fn ignore(data: &[u8; BUFSIZE], len: usize) -> bool {
    if len > 0 && data[0] != b'/' {
        // Ignore relative paths, we can't deal with them anyway.
        true
    }
    // "libssl.so.[0-9]\0"
    else if len > 12 &&
        data[len-12] == b'l' &&
        data[len-11] == b'i' &&
        data[len-10] == b'b' &&
        data[len- 9] == b's' &&
        data[len- 8] == b's' &&
        data[len- 7] == b'l' &&
        data[len- 6] == b'.' &&
        data[len- 5] == b's' &&
        data[len- 4] == b'o' &&
        data[len- 3] == b'.' {
         false
    }
    // "libssl.so.[0-9].[0.9]\0"
    else if len > 12 &&
        data[len-14] == b'l' &&
        data[len-13] == b'i' &&
        data[len-12] == b'b' &&
        data[len-11] == b's' &&
        data[len-10] == b's' &&
        data[len- 9] == b'l' &&
        data[len- 8] == b'.' &&
        data[len- 7] == b's' &&
        data[len- 6] == b'o' &&
        data[len- 5] == b'.' {
         false
    }
    // Node links OpenSSL in, so also look at "libnode.so.[0-9][0-9]\0"
    else if len > 14 &&
        data[len-14] == b'l' &&
        data[len-13] == b'i' &&
        data[len-12] == b'b' &&
        data[len-11] == b'n' &&
        data[len-10] == b'o' &&
        data[len- 9] == b'd' &&
        data[len- 8] == b'e' &&
        data[len- 7] == b'.' &&
        data[len- 6] == b's' &&
        data[len- 5] == b'o' &&
        data[len- 4] == b'.' {
         false
    }
    else {
        true
    }
}
