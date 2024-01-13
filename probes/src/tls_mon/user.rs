use redbpf_probes::uprobe::prelude::*;
use probes::tls_mon::*;

// Note that we also have SSL_write_ex and (yay, fun) SSL_sendfile to contend with.
// SSL_sendfile requires kernel mode TLS and I don't think that that is very common. Don't
// know about SSL_write_ex and SSL_read_ex.

// Also note that with these three functions, we don't measure socket connect() time,
// which can be long to very long. Given that the focus is on discovery for now,
// that is not yet a major issue.

// All functions in here _MUST_ be the same as the library function names they probe!

// int SSL_write(SSL *ssl, const void *buf, size_t num)
#[allow(unused_must_use, non_snake_case)]
#[uprobe]
fn SSL_write(regs: Registers) {
    unsafe {
        let mut event = TMP_EVENT.get_mut(0).unwrap();
        event.kind = Kind::Write;
        event.handle = regs.parm1();
        event.ts = bpf_ktime_get_ns();

        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
        event.tgid = (pid_tgid >> 32) as u32;

        let data = regs.parm2() as *const u8;
        let len = regs.parm3() as i64;
        let err =
            bpf_probe_read_user(
                event.data.as_mut_ptr() as *mut _,
                if len < 0 || len > (BUFSIZE as i64) { BUFSIZE as u32 } else { len as u32 },
                data as *const _);
        if err < 0 {
            printk!("error %lld on bpf_probe_read_user_str", err);
        } else {
            event.len = regs.parm3() as usize;
            TLS_BUF.insert(regs.ctx, &event);
        }
    }
}

// int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
#[allow(unused_must_use, non_snake_case)]
#[uprobe]
fn SSL_write_ex(regs: Registers) {
    unsafe {
        let mut event = TMP_EVENT.get_mut(0).unwrap();
        event.kind = Kind::Write;
        event.handle = regs.parm1();
        event.ts = bpf_ktime_get_ns();

        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
        event.tgid = (pid_tgid >> 32) as u32;

        let data = regs.parm2() as *const u8;
        let len = regs.parm3() as i64;
        let err =
            bpf_probe_read_user(
                event.data.as_mut_ptr() as *mut _,
                if len < 0 || len > (BUFSIZE as i64) { BUFSIZE as u32 } else { len as u32 },
                data as *const _);
        if err < 0 {
            printk!("error %lld on bpf_probe_read_user_str", err);
        } else {
            event.len = regs.parm3() as usize;
            TLS_BUF.insert(regs.ctx, &event);
        }
    }
}

//  int SSL_read(SSL *ssl, void *buf, int num);
#[allow(unused_must_use, non_snake_case)]
#[uretprobe]
fn SSL_read(regs: Registers, parms: [u64; 5]) {
    unsafe {
        let mut event = TMP_EVENT.get_mut(0).unwrap();
        event.kind = Kind::Read;
        event.handle = parms[0];
        event.ts = bpf_ktime_get_ns();

        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
        event.tgid = (pid_tgid >> 32) as u32;

        let data = parms[1] as *const u8;
        let len = regs.rc() as i64;
        if len > 0 {
            let err =
                bpf_probe_read_user(
                    event.data.as_mut_ptr() as *mut _,
                    if len < 0 || len > (BUFSIZE as i64) { BUFSIZE as u32 } else { len as u32 },
                    data as *const _);
            if err < 0 {
                printk!("error %lld on bpf_probe_read_user_str", err);
            } else {
                event.len = len as usize;
                TLS_BUF.insert(regs.ctx, &event);
            }
        }
    }
}

//  int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
#[allow(unused_must_use, non_snake_case)]
#[uretprobe]
fn SSL_read_ex(regs: Registers, parms: [u64; 5]) {
    unsafe {
        let mut event = TMP_EVENT.get_mut(0).unwrap();
        event.kind = Kind::Read;
        event.handle = parms[0];
        event.ts = bpf_ktime_get_ns();

        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
        event.tgid = (pid_tgid >> 32) as u32;

        let data = parms[1] as *const u8;
        let mut len: u32 = 0;
        let len_ptr = &mut len as *mut _ as *mut c_void;
        let err =
            bpf_probe_read_user(
                len_ptr,
                4, // TODO we don't have std::mem::sizeof and we still want to be cross-platform.
                parms[3] as *const _);
        if err < 0 {
            printk!("error %lld reading length", err);
        }
        else {
            if len > 0 {
                let err =
                    bpf_probe_read_user(
                        event.data.as_mut_ptr() as *mut _,
                        if len > (BUFSIZE as u32) { BUFSIZE as u32 } else { len as u32 },
                        data as *const _);
                if err < 0 {
                    printk!("error %lld on bpf_probe_read_user_str", err);
                } else {
                    event.len = len as usize;
                    TLS_BUF.insert(regs.ctx, &event);
                }
            }
        }
    }
}

#[allow(non_snake_case)]
#[uretprobe]
fn SSL_new(regs: Registers) {
    unsafe {
        let mut event = TMP_EVENT.get_mut(0).unwrap();

        event.kind = Kind::New;
        event.ts = bpf_ktime_get_ns();
        event.handle = regs.rc();

        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
        event.tgid = (pid_tgid >> 32) as u32;

        TLS_BUF.insert(regs.ctx, &event);
    }
}

#[allow(non_snake_case)]
#[uprobe]
fn SSL_free(regs: Registers) {
    unsafe {
        let mut event = TMP_EVENT.get_mut(0).unwrap();

        event.kind = Kind::Free;
        event.handle = regs.parm1();
        event.ts = bpf_ktime_get_ns();

        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid & 0xFFFFFFFF) as u32;
        event.tgid = (pid_tgid >> 32) as u32;

        TLS_BUF.insert(regs.ctx, &event);
    }
}
