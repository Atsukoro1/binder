use std::fs;

use pe_helpers::is_valid_pe_file;

mod pe_sections;
mod pe_helpers;
mod crypt;

fn main() {
    let encrypted_data = pe_sections::get_data_sections().to_vec();
    let key = pe_sections::get_key_section();

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
    
    fs::write("./file_one.decrypted.exe", first_file).unwrap();
    fs::write("./file_two.decrypted.exe", second_file).unwrap();

    println!("Files successfully decrypted!");
}