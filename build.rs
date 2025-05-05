use object::{
    write::{Object, SectionId, Symbol, SymbolSection},
    Architecture, BinaryFormat, Endianness, SectionKind,
};
use rand::Rng;
use std::{env, fs, path::Path};

fn create_object_symbol(symbol_name: Vec<u8>, section_id: SectionId, value: u64) -> Symbol {
    Symbol {
        name: symbol_name,
        value: value,
        size: 0,
        kind: object::SymbolKind::Data,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section_id),
        flags: object::SymbolFlags::None,
    }
}

fn generate_encryption_key() -> [u8; 20] {
    let mut encr_key: [u8; 20] = [32; 20];

    for i in 1..20 {
        encr_key[i] = rand::thread_rng().gen_range(0..255);
    }

    encr_key
}

fn xor_data(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn get_file_bytes(file_path: &str) -> Vec<u8> {
    let raw_file_bytes = fs::read(file_path).unwrap().to_vec();

    raw_file_bytes
}

fn main() {
    let secret_key = generate_encryption_key();

    let mut first_file = get_file_bytes("./files/file_one.exe");
    let mut second_file = get_file_bytes("./files/file_two.exe");

    xor_data(&mut first_file, &secret_key);
    xor_data(&mut second_file, &secret_key);

    let secret_data = [first_file.clone(), second_file.clone()].concat();

    let mut obj = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);

    let data_section_id = obj.add_section(Vec::new(), b".encrypt".to_vec(), SectionKind::Data);

    // Symbols for runtime to later know where to start / end reading data
    obj.add_symbol(create_object_symbol(
        b"__encrypt_start".to_vec(),
        data_section_id,
        0,
    ));
    obj.add_symbol(create_object_symbol(
        b"__encrypt_end".to_vec(),
        data_section_id,
        secret_data.len() as u64,
    ));

    let file_ending_pos = first_file.len() as u64;

    let pos_data = file_ending_pos.to_le_bytes();

    let data_section = obj.section_mut(data_section_id);

    data_section.append_data(&pos_data, 8);
    data_section.append_data(secret_data.as_slice(), 1);

    // Store encryption key into a section to be accessed in runtime
    let key_section_id = obj.add_section(Vec::new(), b".key".to_vec(), SectionKind::Data);
    let key_section = obj.section_mut(key_section_id);
    let key_offset = key_section.append_data(&secret_key, 1);

    obj.add_symbol(create_object_symbol(
        b"__key_start".to_vec(),
        key_section_id,
        key_offset,
    ));

    let out_dir = env::var("OUT_DIR").unwrap();
    let obj_path = Path::new(&out_dir).join("custom_sections.obj");
    fs::write(&obj_path, obj.write().unwrap()).unwrap();

    println!("cargo:rustc-link-arg={}", obj_path.display());
    println!("cargo:rerun-if-changed=build.rs");
}
