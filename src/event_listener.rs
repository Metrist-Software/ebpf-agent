/// This is where the event listening work happens. We run a
/// thread that reads the event stream and processes it.
use crate::open_listener::OpenMsg;
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::Stream;
use futures::stream::StreamExt;
use probes::tls_mon::Kind;
use probes::tls_mon::TlsEvent;
use redbpf::load::map_io::PerfMessageStream;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::Path;
use std::ptr;
use std::time::Instant;
use sysinfo::PidExt;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

// Here we keep some data about state of an SSL handle around
// so we know where we are.
struct Handle {
    is_h2: bool,
    pid: u32,
    // For HTTP/1.1, we keep state here.
    start_ns: u64,
    last_ns: u64,
    method: String,
    url: String,
    host: String,
    // For HTTP/2, we keep state here.
    streams: HashMap<u32, Handle>,
    decoder: h2::hpack::Decoder,
}

#[allow(unused_must_use)]
pub fn start_event_listener(
    event_stream: UnboundedReceiver<(String, <PerfMessageStream as Stream>::Item)>,
    sock: UdpSocket,
    tx: Sender<OpenMsg>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_event_listener(event_stream, sock, tx).await;
    })
}

#[allow(unused_must_use)]
async fn run_event_listener(
    mut event_stream: UnboundedReceiver<(String, <PerfMessageStream as Stream>::Item)>,
    sock: UdpSocket,
    tx: Sender<OpenMsg>,
) {
    let mut handles = HashMap::new();
    println!("Listening for eBPF events ...");
    let mut last_cleanup = Instant::now();
    while let Some((_name, events)) = event_stream.next().await {
        for event in events {
            if last_cleanup.elapsed().as_secs() > 60 {
                let pre_len = handles.len();
                handles.retain(|_, h: &mut Handle| Path::new(format!("/proc/{}", h.pid).as_str()).is_dir());
                let post_len = handles.len();
                println!("Cleanup: Cleaned {} handles, remaining {}, capacity {}",
                         pre_len - post_len,
                         post_len,
                         handles.capacity());

                last_cleanup = Instant::now();
            }
            let tls_event = unsafe { ptr::read(event.as_ptr() as *const TlsEvent) };
            let mut do_print = false;
            match tls_event.kind {
                Kind::New => {
                    let hdl = Handle {
                        pid: tls_event.pid,
                        ..Default::default()
                    };
                    handles.insert(tls_event.handle, hdl);
                }
                Kind::Write => {
                    if let Some(handle) = handles.get_mut(&tls_event.handle) {
                        maybe_update_protocol_data(handle, &tls_event);
                    }
                }
                Kind::Read => {
                    // on every read, we update the timestamp. Then, the next write
                    // or the free indicates that that was the last read, and we use
                    // that timestamp to emit a message. This way, we don't need to
                    // parse the protocol.
                    if let Some(handle) = handles.get_mut(&tls_event.handle) {
                        if handle.is_h2 {
                            let head = h2::frame::Head::parse(&tls_event.data);
                            let stream_id = head.stream_id().value();
                            if stream_id > 0 {
                                if let Some(stream_handle) = handle.streams.get_mut(&stream_id) {
                                    stream_handle.last_ns = tls_event.ts;
                                    if (head.kind() == h2::frame::Kind::Headers
                                        || head.kind() == h2::frame::Kind::Data)
                                        && head.flag() & 0x01 == 0x01
                                    {
                                        let delta_ns =
                                            stream_handle.last_ns - stream_handle.start_ns;
                                        send_stats_line(&sock, stream_handle, delta_ns);
                                    }
                                }
                            }
                        } else {
                            handle.last_ns = tls_event.ts;
                        }
                    }
                }
                Kind::Free => {
                    if let Some(handle) = handles.get(&tls_event.handle) {
                        if !handle.is_h2 {
                            if handle.start_ns > 0 {
                                // If we had a last read, we use that as the timestamp because it is likely to
                                // be more precise measurement of the transaction than waiting for whenever
                                // the caller gets around freeing this.
                                let last_ns = if handle.last_ns > 0 {
                                    handle.last_ns
                                } else {
                                    tls_event.ts
                                };
                                let delta_ns = last_ns - handle.start_ns;
                                send_stats_line(&sock, handle, delta_ns);
                            }
                        }

                        handles.remove(&tls_event.handle);
                    }
                }
                Kind::OpenAt => {
                    // The string is null-terminated
                    // so we chop off the last bit.
                    do_print = true;
                    let cdata = &tls_event.data[0..tls_event.len - 1];
                    let buf = String::from_utf8_lossy(&cdata);
                    if tls_event.len > 0 {
                        if tls_event.tgid == sysinfo::get_current_pid().unwrap().as_u32() {
                            // We don't need to deal with our own open() calls that are caused
                            // by us probing the library.
                            do_print = false;
                        } else {
                            let msg = OpenMsg {
                                lib_name: buf.to_string(),
                                pid: tls_event.pid,
                            };
                            tx.send(msg).await;
                        }
                    }
                }

                Kind::Unset => {
                    println!("Unexpected packet with [Unset] kind!");
                    do_print = true;
                }
            }
            if do_print {
                println!(
                    "{:?} -- ts {}/pid {}/tgid {}/hdl {}: {} bytes",
                    tls_event.kind,
                    tls_event.ts,
                    tls_event.pid,
                    tls_event.tgid,
                    tls_event.handle,
                    tls_event.len
                );
                // A read can (and will) return -1 bytes, so ignore that.
                if tls_event.len > 0 && tls_event.len != 0xffffffff {
                    let cdata = &tls_event.data[0..tls_event.len];
                    hexdump::hexdump(&cdata);
                }
            }
        }
    }
}

fn maybe_update_protocol_data(handle: &mut Handle, event: &TlsEvent) {
    if is_h2_hdr(event) {
        handle.is_h2 = true;
        return;
    }

    if handle.is_h2 {
        let head = h2::frame::Head::parse(&event.data);
        if head.kind() == h2::frame::Kind::Headers {
            let cdata = &event.data[h2::frame::HEADER_LEN..event.len];
            let bm = bytes::BytesMut::from(cdata);
            let (mut headers, mut rest) =
                h2::frame::Headers::load(head, bm).expect("Cannot parse headers");
            let stream_id = headers.stream_id().value();
            let result = headers.load_hpack(&mut rest, 16 << 20, &mut handle.decoder);
            println!("Headers: {:?}", headers);
            println!(" parse result: {:?}", result);
            let (pseudo, _fields) = headers.into_parts();

            let mut stream_handle = Handle {
                ..Default::default()
            };
            stream_handle.method = String::from(pseudo.method.unwrap_or_default().as_str());
            stream_handle.host =
                String::from_utf8_lossy(pseudo.authority.unwrap_or_default().as_ref()).to_string();
            stream_handle.url =
                String::from_utf8_lossy(pseudo.path.unwrap_or_default().as_ref()).to_string();
            // Reset timings on a new stream
            stream_handle.last_ns = 0;
            stream_handle.start_ns = event.ts;

            handle.streams.insert(stream_id, stream_handle);
        }
    } else {
        let cdata = &event.data[0..event.len];
        let buf = String::from_utf8_lossy(&cdata);
        for line in buf.lines() {
            let lower = line.to_ascii_lowercase();
            let elems: Vec<&str> = line.split_ascii_whitespace().collect();

            if lower.starts_with("host: ") {
                handle.host = (&line[6..]).to_string();
            }
            if elems.len() == 3 && is_method(elems[0]) {
                handle.method = String::from(elems[0]);
                handle.url = String::from(elems[1]);
            }
        }
        // Reset timings on write.
        handle.last_ns = 0;
        handle.start_ns = event.ts;
    }
}

#[allow(unused_must_use)]
fn send_stats_line(sock: &UdpSocket, handle: &Handle, delta_ns: u64) {
    let delta_ms = delta_ns as f32 / (1000.0 * 1000.0);
    let msg = format!(
        "0\t{}\t{}\t{}\t{}\n",
        handle.method, handle.host, handle.url, delta_ms
    );
    sock.send(msg.as_bytes());
    println!("++ seen {}", msg);
}

fn is_method(method: &str) -> bool {
    match method {
        "GET" => true,
        "HEAD" => true,
        "PUT" => true,
        "POST" => true,
        &_ => false,
    }
}

const H2_HDR_LEN: usize = 24;
const H2_HDR: [u8; H2_HDR_LEN] = [
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
];

fn is_h2_hdr(event: &TlsEvent) -> bool {
    event.len >= H2_HDR_LEN && event.data[0..24] == H2_HDR
}

impl Default for Handle {
    fn default() -> Handle {
        Handle {
            is_h2: false,
            pid: 0,
            start_ns: 0,
            last_ns: 0,
            method: String::from(""),
            url: String::from(""),
            host: String::from(""),
            streams: HashMap::new(),
            decoder: h2::hpack::Decoder::new(2048),
        }
    }
}
