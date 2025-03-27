#![no_std]

pub const NAME_MAX_LEN:usize = 128;
pub struct OpenLog {
    pub filename: [u8;NAME_MAX_LEN],
    pub pid: u32,
    pub errno: u64,
    pub comm: [u8;16],
    pub fd: u64,
}

