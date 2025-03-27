#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use opensnoop_common::{OpenLog, NAME_MAX_LEN};
use opensnoop_ebpf::read_at;

#[map]
static OPEN_MAPS: HashMap<u64, [u8; NAME_MAX_LEN]> = HashMap::with_max_entries(1024, 0);

#[map(name = "open_events")]
static OPEN_EVENTS: PerfEventArray<OpenLog> = PerfEventArray::new(0);

#[tracepoint]
pub fn sys_exit_open(ctx: TracePointContext) -> u32 {
    match try_sys_exit_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    // ret 的偏移和大小一样
    match try_sys_exit_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/**
 *
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_open/format
name: sys_exit_open
ID: 768
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret

sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
name: sys_exit_openat
ID: 766
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret

 */
fn try_sys_exit_open(ctx: TracePointContext) -> Result<u32, u32> {
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let ret: i64 = read_at(&ctx, 16)?;
    let errno: u64 = if ret >= 0 { ret as u64 } else { -ret as u64 };
    let filename = unsafe {
        OPEN_MAPS
            .get(&tid)
            .ok_or(0u32)
            .map_err(|e| -> u32 {
                // helpers::bpf_printk!(b"failed to get tid=%lu .......", tid);
                e
            })?
            .clone()
    };
    let _ = OPEN_MAPS.remove(&tid);
    let data = OpenLog {
        errno,
        filename,
        pid: ctx.pid(),
        fd: ret as u64,
        comm: ctx.command().map_err(|e| {
            unsafe {
                helpers::bpf_printk!(b"ctx.command() err=%ld tid=%lu .......", e, tid);
            }
            e as u32
        })?,
    };
    OPEN_EVENTS.output(&ctx, &data, 0);
    let _ = OPEN_MAPS.remove(&tid);
    Ok(0)
}

/**
 *
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
name: sys_enter_open
ID: 769
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:int flags;        offset:24;      size:8; signed:0;
        field:umode_t mode;     offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

 */
fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, u32> {
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let filename_ptr: *const u8 = read_at(&ctx, 16).map_err(|e| e)?;
    let mut filename: [u8; NAME_MAX_LEN] = [0; NAME_MAX_LEN];
    unsafe {
        let _ = helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut filename)
            .map_err(|e| e as u32)?;
    };
    OPEN_MAPS.insert(&tid, &filename, 0).map_err(|e| e as u32)?;
    Ok(0)
}

/**
 *
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
name: sys_enter_openat
ID: 767
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))


 */
fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let filename_ptr: *const u8 = read_at(&ctx, 24).map_err(|e| e)?;
    let mut filename: [u8; NAME_MAX_LEN] = [0; NAME_MAX_LEN];
    unsafe {
        let _ = helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut filename)
            .map_err(|e| e as u32)?;
    };
    OPEN_MAPS.insert(&tid, &filename, 0).map_err(|e| e as u32)?;
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
