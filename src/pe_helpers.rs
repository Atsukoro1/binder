/// All valid PE files start with MZ prefix, check for it
pub fn is_valid_pe_file(pe_data: &[u8]) -> bool {
    if pe_data.starts_with(b"MZ") {
        return true;
    }

    false
}