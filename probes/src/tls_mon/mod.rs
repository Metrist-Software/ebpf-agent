use redbpf_probes::kprobe::prelude::*;

// This should be enough to get at the Hostname and URL in a packet.
// We try to keep the size at under 4k.
pub const BUFSIZE: usize = 4000;

#[map]
pub static mut TMP_EVENT: PerCpuArray<TlsEvent> = PerCpuArray::with_max_entries(1);

// Even though it says "entries", it is actually bytes. Or words, rather, so this
// map takes 8MB of kernel memory and can store around 950 TlsEvents. We can optimize
// memory usage by writing smaller open events and/or doing some preprocessing for
// SSL_write calls that we don't want (typically, the packet will start with GET/PUT/POST/HEAD
// and we can scan for that and just not send it out)
#[map]
pub static mut TLS_BUF: PerfMap<TlsEvent> = PerfMap::with_max_entries(1000000);

#[repr(C)]
#[derive(Debug, Clone)]
pub enum Kind {
    Unset,
    New,
    Write,
    Free,
    Read,
    OpenAt
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TlsEvent {
    // Basic identifying data
    pub kind: Kind,
    pub pid: u32,
    pub tgid: u32,
    pub ts: u64,
    pub handle: u64,
    pub len: usize,
    pub data: [u8; BUFSIZE]
}

impl Default for TlsEvent {
    fn default() -> TlsEvent {
        TlsEvent {
            kind: Kind::Unset,
            pid: 0,
            tgid: 0,
            handle: 0,
            ts: 0,
            data: [0; BUFSIZE],
            len: 0
        }
    }
}
