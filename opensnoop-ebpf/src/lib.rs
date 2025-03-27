#![no_std]

use aya_ebpf::programs::TracePointContext;

// This file exists to enable the library target.



pub fn read_at<T>(ctx: &TracePointContext, offset: usize)->Result<T, u32>{
    unsafe {
        ctx.read_at(offset).map_err(|e|e as u32)
    }
}