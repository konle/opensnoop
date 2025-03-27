use aya::{maps::{AsyncPerfEventArray, PerfEventArray}, programs::TracePoint, util::online_cpus, Ebpf};
#[rustfmt::skip]
use log::{debug, warn};
use opensnoop_common::OpenLog;
use tokio::signal;

use opensnoop::cstr_slice_2_rstr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/opensnoop"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let sys_exit_open_program: &mut TracePoint = ebpf.program_mut("sys_exit_open").unwrap().try_into()?;
    sys_exit_open_program.load()?;
    sys_exit_open_program.attach("syscalls", "sys_exit_open")?;
    let sys_enter_open_program: &mut TracePoint = ebpf.program_mut("sys_enter_open").unwrap().try_into()?;
    sys_enter_open_program.load()?;
    sys_enter_open_program.attach("syscalls", "sys_enter_open")?;
    let sys_enter_openat_program: &mut TracePoint = ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    sys_enter_openat_program.load()?;
    sys_enter_openat_program.attach("syscalls", "sys_enter_openat")?;
    let sys_exit_openat_program: &mut TracePoint = ebpf.program_mut("sys_exit_openat").unwrap().try_into()?;
    sys_exit_openat_program.load()?;
    sys_exit_openat_program.attach("syscalls", "sys_exit_openat")?;
    //
    opensnoop::deal_event(&mut ebpf);
 
/*
    for cpu_id in online_cpus().unwrap(){
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::task::spawn(async move{
            let mut buffers = (0..10)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop{
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read{
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as * const OpenInfo;
                    let data = unsafe {
                        ptr.read_unaligned()
                    };
                    let comm = cstr_slice_2_rstr(&data.comm);
                    let filename = cstr_slice_2_rstr(&data.filename);
                    println!("{}({}) open {}({}) return {}",comm, data.pid, filename, data.fd, data.errno);
                }
            }
        });
    }
     */


    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
