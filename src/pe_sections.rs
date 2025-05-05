unsafe extern "C" {
    #[link_name = "__encrypt_start"]
    unsafe static ENCRYPT_START: u8;
    #[link_name = "__encrypt_end"]
    unsafe static ENCRYPT_END: u8;
    #[link_name = "__key_start"]
    unsafe static KEY_START: u8;
}

/// Get all data from section ".encrypt", here all PE executable data are stored
pub fn get_data_sections() -> &'static [u8] {
    unsafe {
        let start = &ENCRYPT_START as *const u8;
        let end = &ENCRYPT_END as *const u8;
        let size = end as usize - start as usize;
        std::slice::from_raw_parts(start, size)
    }
}

/// Get encryption key stored in .key section
pub fn get_key_section() -> &'static [u8] {
    unsafe {
        let start = &KEY_START as *const u8;

        std::slice::from_raw_parts(start, 20)
    }
}