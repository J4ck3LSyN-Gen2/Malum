use tokio_uring::net::TcpStream;
use std::net::ToSocketAddrs;
use std::os::unix::io::{RawFd, AsRawFd};
use std::thread;

#[no_mangle]
pub extern "C" fn uring_async_connect(host: *const u8, port: u32) -> RawFd {
    let c_host = unsafe { std::ffi::CStr::from_ptr(host as *const i8) };
    let host_str = match c_host.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };

    let (tx, rx) = std::sync::mpsc::channel();

    thread::spawn(move || {
        tokio_uring::start(async move {
            let addr = match format!("{}:{}", host_str, port).to_socket_addrs() {
                Ok(mut addrs) => addrs.next().unwrap(),
                Err(_) => {
                    let _ = tx.send(-1);
                    return;
                }
            };

            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    let fd = stream.as_raw_fd();
                    // Prevent Rust from closing the fd when dropping
                    std::mem::forget(stream);
                    let _ = tx.send(fd);
                }
                Err(_) => {
                    let _ = tx.send(-1);
                }
            }
        });
    });

    // Wait for the background thread result (non-blocking to Python main thread)
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(fd) => fd,
        Err(_) => -1,
    }
}