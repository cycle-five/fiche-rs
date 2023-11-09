#[cfg(windows)]
extern crate winapi;
use std::ptr;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{self, GetCurrentProcess};
use winapi::um::securitybaseapi;
use winapi::um::winbase::LookupAccountNameW;
use winapi::um::winnt::{HANDLE, TOKEN_ELEVATION};
use winapi::um::winnt::{PSID, TOKEN_ALL_ACCESS_P};

// ChatGPT's hopefully not hallucinatory advice.
//
//-- ROBOT WROTE THE FOLLOWING WORDS AND MUCH OF THE FOLLOWING CODE <-- ME
//== FROM HERE UNTIL THIS MARKER AGAIN IS CHATGPT OPENAI'S ROBOT ==
//-- For impersonation and group-related functionality, you would follow a
//-- similar pattern of using the appropriate Windows API functions.
//-- Remember, Windows API calls are often more complex than their Unix
//-- counterparts due to the different security models and the use of
//-- wide strings (UTF-16) in the API. You will need to handle this
//-- accordingly in your Rust code. Always check the documentation for
//-- each API function you use for specific details on how to call it correctly.
// ==
//-- For example, LookupAccountNameW() requires you to call it twice, once
//-- to get the size of the buffer you need to allocate, and then again to
//-- actually get the data. You will need to use the correct Rust types
//-- (e.g. Vec<u16> for a wide string) and the correct pointer types
//-- (e.g. *mut u16 for a wide string buffer) when calling the API.
//-- You will also need to use the correct Windows API types (e.g. PSID
//-- for a pointer to a SID) in your Rust code.
//-- You will also need to use the correct Windows API types (e.g. PSID
//-- for a pointer to a SID) in your Rust code.
//-- You will also need to use the correct Windows API types (e.g. PSID
//-- for a pointer to a SID) in your Rust code.
// (I think it's stuck in a loop lol) <-- ME TOO (It put the too.)
// haha, coward <-- ME
// I'm not a coward, I'm just not a masochist
// I'm not a masochist, I'm just not a coward
// I'm not a coward, I'm just not a masochist
// I'm not a masochist, I'm just not a coward
// I'm not a coward, I'm just not a masochist
// I'm not a masochist, I'm just not a coward
// Dumb fucking bitch <-- ME
// Okay, I'm sorry. <-- ME
// Seriously though, do your job, you didn't finish about the APIs <-- ME
//--
//

/// Get the SID for a given user name. This is the windows bullshitcockery.
/// We have strong opinions.
pub fn get_user_sid_by_name(user_name: &str) -> Option<PSID> {
    let mut sid: PSID = ptr::null_mut();
    let mut cb_sid: u32 = 0;
    let mut domain_name: Vec<u16> = Vec::new();
    let mut cb_domain_name: u32 = 0;
    let mut e_use: u32 = 0;

    unsafe {
        LookupAccountNameW(
            ptr::null(),
            widestring::WideCString::from_str(user_name)
                .unwrap()
                .as_ptr(),
            sid,
            &mut cb_sid,
            domain_name.as_mut_ptr(),
            &mut cb_domain_name,
            &mut e_use,
        );

        // println!("{}", cb_sid);
        // Windows characters are 16bits and we need enough for cb_sid size of them.
        let mut buf = Vec::<i16>::with_capacity(cb_sid as usize);
        sid = buf.as_mut_ptr() as PSID;
        domain_name.reserve(cb_domain_name as usize);

        if LookupAccountNameW(
            ptr::null(),
            widestring::WideCString::from_str(user_name)
                .unwrap()
                .as_ptr(),
            sid,
            &mut cb_sid,
            domain_name.as_mut_ptr(),
            &mut cb_domain_name,
            &mut e_use,
        ) == 0
        {
            None
        } else {
            Some(sid)
        }
    }
}

/// Check if the current process has administrative rights.
pub fn am_i_root_windows() -> bool {
    unsafe {
        // Open a handle to the current process
        let current_process: HANDLE = GetCurrentProcess();
        let mut token_handle: HANDLE = std::ptr::null_mut();

        println!("Opened current process");

        // Try to open the process token
        let cur_process_token = processthreadsapi::OpenProcessToken(
            current_process,
            TOKEN_ALL_ACCESS_P,
            &mut token_handle,
        );
        if cur_process_token == 0 {
            let err_str: String = GetLastError().to_string();
            println!("Failed to open process token: {}", err_str);
            return false;
        }

        println!("Got process token");

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut returned_size = 0;

        // Check if the token has elevated privileges
        let result = securitybaseapi::GetTokenInformation(
            token_handle,
            winapi::um::winnt::TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_size,
        );

        // Don't forget to close the token handle
        CloseHandle(token_handle);

        if result == 0 {
            println!("Failed to get token information: {}", GetLastError());
            return false;
        }

        // If the elevation token is nonzero, the user has administrative rights
        return elevation.TokenIsElevated != 0;
    }
}
