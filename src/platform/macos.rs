use sysctl::Sysctl;

use crate::utils::{is_ipv6, pre_condition};
use crate::NetworkProtocol;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicUsize;
use std::sync::Once;

const SYS_PROC_INFO: i32 = 336;
const PROCPIDPATHINFO: i32 = 0xb;
const PROCPIDPATHINFOSIZE: usize = 1024;
const PROCCALLNUMPIDINFO: i32 = 0x2;

static STRUCT_SIZE: AtomicUsize = AtomicUsize::new(0);
static STRUCT_SIZE_SETTER: Once = Once::new();

pub fn find_process_name(
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
    proto: NetworkProtocol,
) -> Option<String> {
    find_process_name_inner(src, dst, proto).ok()
}

fn find_process_name_inner(
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
    proto: NetworkProtocol,
) -> Result<String, io::Error> {
    if !pre_condition(src, dst) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid input"));
    }
    STRUCT_SIZE_SETTER.call_once(|| {
        let default = "".to_string();
        let ctl = sysctl::Ctl::new("kern.osrelease").unwrap();
        let value = ctl.value().unwrap();
        let buf = value.as_string().unwrap_or(&default);
        let buf = buf.split('.').collect::<Vec<&str>>();
        let major = buf[0].parse::<i32>().unwrap();
        if major >= 22 {
            STRUCT_SIZE.store(408, std::sync::atomic::Ordering::Relaxed);
        } else {
            STRUCT_SIZE.store(384, std::sync::atomic::Ordering::Relaxed);
        }
    });

    // see: https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/netinet/in_pcblist.c#L292
    let spath = match proto {
        NetworkProtocol::TCP => "net.inet.tcp.pcblist_n",
        NetworkProtocol::UDP => "net.inet.udp.pcblist_n",
    };

    let is_ipv4 = !is_ipv6(src, dst);

    let ctl = sysctl::Ctl::new(spath).unwrap();
    let value = ctl.value().unwrap();
    let buf = value.as_struct().unwrap();
    let struct_size = STRUCT_SIZE.load(std::sync::atomic::Ordering::Relaxed);
    let item_size = struct_size
        + if proto == NetworkProtocol::TCP {
            208
        } else {
            0
        };

    // see https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/netinet/in_pcb.h#L451
    // offset of flag is 44
    // offset of foreign port is 16
    // offset of local port is 18
    // end offset of foreign address is 64
    // end offset of local address is 80
    for i in (24..buf.len()).step_by(item_size) {
        if i + item_size > buf.len() {
            break;
        }
        let inp = i;
        let so = i + 104;

        let dst_port = u16::from_be_bytes([buf[inp + 16], buf[inp + 17]]);
        let src_port = u16::from_be_bytes([buf[inp + 18], buf[inp + 19]]);
        let flag = buf[inp + 44];
        let dst_ip = match flag {
            0x1 if is_ipv4 => {
                let start = inp + 60;
                let end = start + 4;
                let mut addr = [0; 4];
                addr.copy_from_slice(&buf[start..end]);
                IpAddr::from(Ipv4Addr::from(addr))
            }
            0x2 if !is_ipv4 => {
                let start = inp + 48;
                let end = start + 16;
                let mut addr = [0; 16];
                addr.copy_from_slice(&buf[start..end]);
                IpAddr::from(Ipv6Addr::from(addr))
            }
            _ => continue,
        };
        let src_ip = match flag {
            0x1 if is_ipv4 => {
                let start = inp + 76;
                let end = start + 4;
                let mut addr = [0; 4];
                addr.copy_from_slice(&buf[start..end]);
                IpAddr::from(Ipv4Addr::from(addr))
            }
            0x2 if !is_ipv4 => {
                let start = inp + 64;
                let end = start + 16;
                let mut addr = [0; 16];
                addr.copy_from_slice(&buf[start..end]);
                IpAddr::from(Ipv6Addr::from(addr))
            }
            _ => continue,
        };

        if let Some(addr) = src {
            if addr.port() != src_port || addr.ip() != src_ip {
                continue;
            }
        }
        if let Some(addr) = dst {
            if addr.port() != dst_port || addr.ip() != dst_ip {
                continue;
            }
        }

        // TODO: support unspec address
        let pp = get_exec_path_from_pid(get_pid(&buf[so + 68..so + 72]))?;
        return Ok(pp);
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Process not found"))
}

fn get_pid(bytes: &[u8]) -> u32 {
    assert_eq!(bytes.len(), 4);
    let mut pid_bytes = [0; 4];
    pid_bytes.copy_from_slice(bytes);
    if cfg!(target_endian = "big") {
        u32::from_be_bytes(pid_bytes)
    } else {
        u32::from_le_bytes(pid_bytes)
    }
}

fn get_exec_path_from_pid(pid: u32) -> Result<String, io::Error> {
    let mut buf = vec![0u8; PROCPIDPATHINFOSIZE];
    let ret = unsafe {
        libc::syscall(
            SYS_PROC_INFO,
            PROCCALLNUMPIDINFO,
            pid as usize,
            PROCPIDPATHINFO,
            0,
            buf.as_mut_ptr() as usize,
            PROCPIDPATHINFOSIZE,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&x| x == 0).unwrap();
    let path = String::from_utf8_lossy(&buf[0..len]).into_owned();
    Ok(path)
}
