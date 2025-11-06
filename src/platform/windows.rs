// SPDX-License-Identifier: MIT

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;

use crate::utils::{is_ipv6, pre_condition};
use crate::NetworkProtocol;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn find_process_name(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
    proto: NetworkProtocol,
) -> Option<String> {
    find_process_name_inner(src, dst, proto).ok()
}

fn find_process_name_inner(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
    proto: NetworkProtocol,
) -> Result<String, io::Error> {
    if !pre_condition(src, dst) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid input"));
    }

    let is_ipv4 = !is_ipv6(src, dst);
    let pid = match proto {
        NetworkProtocol::TCP => {
            if is_ipv4 {
                find_tcp_v4_pid(src, dst)?
            } else {
                find_tcp_v6_pid(src, dst)?
            }
        }
        NetworkProtocol::UDP => {
            if is_ipv4 {
                find_udp_v4_pid(src, dst)?
            } else {
                find_udp_v6_pid(src, dst)?
            }
        }
    };

    get_process_path(pid)
}

fn find_tcp_v4_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;
    
    // First call to get the size
    let result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    
    for i in 0..num_entries {
        let row = unsafe {
            let base_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let entries_ptr = (*base_ptr).table.as_ptr();
            &*entries_ptr.add(i)
        };

        if let Some(addr) = src {
            let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            
            if addr.ip() != IpAddr::V4(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        if let Some(addr) = dst {
            let remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            
            if addr.ip() != IpAddr::V4(remote_addr) || addr.port() != remote_port {
                continue;
            }
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for TCP connection",
    ))
}

fn find_tcp_v6_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;
    
    // First call to get the size
    let result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    
    for i in 0..num_entries {
        let row = unsafe {
            let base_ptr = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
            let entries_ptr = (*base_ptr).table.as_ptr();
            &*entries_ptr.add(i)
        };

        if let Some(addr) = src {
            let local_addr = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            
            if addr.ip() != IpAddr::V6(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        if let Some(addr) = dst {
            let remote_addr = Ipv6Addr::from(row.ucRemoteAddr);
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            
            if addr.ip() != IpAddr::V6(remote_addr) || addr.port() != remote_port {
                continue;
            }
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for TCP connection",
    ))
}

fn find_udp_v4_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;
    
    // First call to get the size
    let result = unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    
    for i in 0..num_entries {
        let row = unsafe {
            let base_ptr = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
            let entries_ptr = (*base_ptr).table.as_ptr();
            &*entries_ptr.add(i)
        };

        if let Some(addr) = src {
            let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            
            if addr.ip() != IpAddr::V4(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        // UDP doesn't have remote address for listeners, so we only check if dst is None
        if dst.is_some() {
            // UDP rows don't have remote address/port, so we can't match destination
            continue;
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for UDP socket",
    ))
}

fn find_udp_v6_pid(
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<u32, io::Error> {
    let mut size: u32 = 0;
    
    // First call to get the size
    let result = unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }

    // Allocate buffer and get the table
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let result = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != NO_ERROR {
        return Err(io::Error::last_os_error());
    }

    // Parse the table
    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    
    for i in 0..num_entries {
        let row = unsafe {
            let base_ptr = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
            let entries_ptr = (*base_ptr).table.as_ptr();
            &*entries_ptr.add(i)
        };

        if let Some(addr) = src {
            let local_addr = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            
            if addr.ip() != IpAddr::V6(local_addr) || addr.port() != local_port {
                continue;
            }
        }

        // UDP doesn't have remote address for listeners, so we only check if dst is None
        if dst.is_some() {
            // UDP rows don't have remote address/port, so we can't match destination
            continue;
        }

        return Ok(row.dwOwningPid);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Process not found for UDP socket",
    ))
}

fn get_process_path(pid: u32) -> Result<String, io::Error> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buffer: Vec<u16> = vec![0; 260]; // MAX_PATH
        let mut size = buffer.len() as u32;

        let result = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        
        // Close handle
        CloseHandle(handle);

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        // Convert UTF-16 to String
        let path = String::from_utf16_lossy(&buffer[..size as usize]);
        Ok(path)
    }
}
