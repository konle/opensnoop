use aya::{maps::{perf::PerfEventArrayBuffer, PerfEventArray, MapData}, util::online_cpus, Ebpf};
use log::warn;
use opensnoop_common::OpenLog;

pub fn cstr_slice_2_rstr(cchr: &[u8]) -> String{
    if let Some(idx) = cchr.iter().position(|&x|x==0){
        return cchr[0..idx].iter().map(|&s| (s as u8) as char).collect::<String>();
    }
    cchr.iter().map(|&s| (s as u8) as char).collect::<String>()
}

pub fn read_event(cpu_id:u32, mut buf: PerfEventArrayBuffer<&mut MapData>)->anyhow::Result<()>{
    let mut data = [bytes::BytesMut::with_capacity(1)];
    loop{
        let events = buf.read_events(&mut data);
        match events{
            Ok(events)=>{
                for event in &data[..events.read]{
                    let ptr = event.as_ptr() as * const OpenLog;
                    let data = unsafe {
                        ptr.read_unaligned()
                    };
                    let comm = cstr_slice_2_rstr(&data.comm);
                    let filename = cstr_slice_2_rstr(&data.filename);
                    println!("{}({}) open {}({}) return {}",comm, data.pid, filename, data.fd, data.errno);
                }
            },
            Err(e)=>{
                warn!("failed to read event: {}",e);
            }
        }
        break;
    }
    Ok(())
}

pub fn deal_event(ebpf: &mut Ebpf)->anyhow::Result<()>{
    let mut events =  PerfEventArray::try_from(ebpf.map_mut("open_events").unwrap() )?;
    loop {
        for cpu_id in online_cpus().map_err(|e| e.1)? {
            let buf = events.open(cpu_id, None)?;
            read_event(cpu_id, buf);
            // tokio::spawn(
            //     async move { read_event(cpu_id, buf).await },
            // );
        }
    }

    Ok(())
}