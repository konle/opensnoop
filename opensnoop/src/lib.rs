use aya::{
    maps::{perf::AsyncPerfEventArrayBuffer, AsyncPerfEventArray, MapData},
    util::online_cpus,
    Ebpf,
};
use log::warn;
use opensnoop_common::OpenLog;

pub fn cstr_slice_2_rstr(cchr: &[u8]) -> String {
    String::from_utf8_lossy(cchr).into_owned()
}

pub async fn read_event(
    _cpu_id: u32,
    mut buf: AsyncPerfEventArrayBuffer<MapData>,
) -> anyhow::Result<()> {
    let mut data = [bytes::BytesMut::with_capacity(1)];
    loop {
        let events = buf.read_events(&mut data).await;
        match events {
            Ok(events) => {
                for event in &data[..events.read] {
                    let ptr = event.as_ptr() as *const OpenLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let comm = cstr_slice_2_rstr(&data.comm);
                    let filename = cstr_slice_2_rstr(&data.filename);
                    println!(
                        "{:>6} {:>16} {:>4} {:>3} {}",
                        data.pid, comm, data.fd, data.errno, filename,
                    );
                }
            }
            Err(e) => {
                warn!("failed to read event: {}", e);
            }
        }
    }
}

pub async fn deal_event(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut events =
        AsyncPerfEventArray::try_from(ebpf.take_map("open_events").ok_or(()).unwrap())?;
    println!("Tracing open syscalls... Hit Ctrl-C to end.");
    println!(
        "{:6} {:16} {:4} {:3} {}",
        "PID", "COMM", "FD", "ERR", "FILENAME"
    );
    for cpu_id in online_cpus().map_err(|e| e.1)? {
        let buf = events.open(cpu_id, None)?;
        tokio::spawn(async move { read_event(cpu_id, buf).await });
    }
    Ok(())
}
