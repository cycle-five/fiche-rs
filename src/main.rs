use rand::Rng;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{self, Duration};

// #[cfg(target_os = "windows")]
// use ::windows;
#[cfg(target_os = "windows")]
use fiche_rs::windows::am_i_root_windows;
// use std::ffi::c_long;
#[cfg(not(target_os = "windows"))]
use std::ffi::CString;
// #[cfg(target_os = "windows")]
// use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
extern crate winapi;

#[cfg(not(target_os = "windows"))]
use ::{
    users::switch::{set_current_gid, set_current_uid},
    users::{get_group_by_name, get_user_by_name},
};

// Define constants
const FICHE_SYMBOLS: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

// Define the FicheError enum
type FicheError = Box<dyn Error + Send + Sync>;

// Define the FicheSettings struct
#[derive(Clone, Debug)]
pub struct FicheSettings {
    pub domain: String,
    pub output_dir: String,
    pub listen_addr: String,
    pub port: u16,
    pub slug_len: usize,
    pub https: bool,
    pub buffer_len: usize,
    pub user_name: Option<String>,
    pub log_file_path: Option<String>,
    pub banlist_path: Option<String>,
    pub whitelist_path: Option<String>,
}

use clap::Parser;
/// semi-sane defaults, the program won't run under these settings howerever.
/// FIXME
impl Default for FicheSettings {
    fn default() -> Self {
        FicheSettings {
            domain: "example.com".to_string(),
            output_dir: "code".to_string(),
            listen_addr: "0.0.0.0".to_string(),
            port: 9999,
            slug_len: 4,
            https: false,
            buffer_len: 32768,
            user_name: None,
            log_file_path: None,
            banlist_path: None,
            whitelist_path: None,
        }
    }
}

/// implements the new method for the FicheSettings struct to parse from
/// command-line arguments.
impl FicheSettings {
    fn new(args: &Args) -> Self {
        FicheSettings {
            domain: args.domain.clone(),
            output_dir: args.output_directory.clone(),
            listen_addr: args.listen.clone(),
            port: args.port,
            slug_len: args.slug_length,
            https: args.ssl,
            buffer_len: args.buffer_length,
            user_name: args.user.clone(),
            log_file_path: args.log.clone(),
            banlist_path: args.banlist.clone(),
            whitelist_path: args.whitelist.clone(),
        }
    }

    #[allow(dead_code)]
    fn user(self, user: String) -> Self {
        Self {
            user_name: Some(user),
            ..self
        }
    }
}
/// The FicheConnection struct represents a connection to the server.
/// It contains the socket, the address of the client, and the settings.
#[derive(Default)]
struct FicheConnection {
    socket: Option<TcpStream>,
    address: Option<SocketAddr>,
    settings: Arc<FicheSettings>,
}

// usage: fiche [-DepbsdolBuw].
//              [-D] [-e] [-d domain] [-p port] [-s slug size]
//              [-o output directory] [-B buffer size] [-u user name]
//              [-l log file] [-b banlist] [-w whitelist]

// Use netcat to push text - example:
// $ cat fiche.c | nc localhost 9999

/// Command-line pastebin for sharing terminal output.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Sets the domain name used in the output URL
    #[arg(short, long)]
    domain: String,

    /// Sets the output directory for saving pasetes
    #[arg(short, long)]
    output_directory: String,

    /// Sets the address to listen on
    #[arg(short, long)]
    listen: String,

    /// Sets the port to listen on
    #[arg(short, long, default_value = "9999")]
    port: u16,

    /// Sets the length of the URL slug
    #[arg(short, long, default_value = "4")]
    slug_length: usize,

    /// Enables HTTPS support
    #[arg(short, long)]
    ssl: bool,

    /// Sets the buffer length
    #[arg(short, long, default_value = "32768")]
    buffer_length: usize,

    /// User to drop privileges to
    #[arg(short, long)]
    user: Option<String>,

    /// Sets the log file path
    #[arg(short, long)]
    log: Option<String>,

    /// banlist file path
    #[arg(short, long)]
    banlist: Option<String>,

    /// whitelist file path
    #[arg(short, long)]
    whitelist: Option<String>,
}

#[cfg(not(tarpaulin_include))]
/// The main function
fn main() -> Result<(), String> {
    // Define the command-line interface using the clap crate

    // Parse the command-line arguments
    let args = Args::parse();

    let settings = FicheSettings::new(&args);
    fiche_run(settings)
}

#[cfg(not(tarpaulin_include))]
/// Continue with the equivalent Rust implementation of fiche_run function
fn fiche_run(mut settings: FicheSettings) -> Result<(), String> {
    // Display welcome message
    let date = chrono::Utc::now();
    print_status(&format!("Starting fiche on {}...", date));

    // Try to set requested user
    if let Err(e) = perform_user_change(&settings) {
        print_error(&format!("Was not able to change the user! {}", e));
        return Err("Failed to change user".to_string());
    }

    // Check if output directory is writable and try to create it
    let output_dir_path = Path::new(&settings.output_dir);
    if !output_dir_path.exists() {
        fs::create_dir_all(output_dir_path).map_err(|e| e.to_string())?;
    }
    if output_dir_path.metadata().unwrap().permissions().readonly() {
        return Err("Output directory not writable!".to_string());
    }

    // Check if log file is writable (if set)
    if let Some(log_file_path) = &settings.log_file_path {
        let log_file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(log_file_path)
            .map_err(|e| e.to_string())?;
        if log_file.metadata().unwrap().permissions().readonly() {
            return Err("Log file not writable!".to_string());
        }
    }

    // Try to set domain name
    set_domain_name(&mut settings);

    // Main loop in this method
    start_server(settings)?;

    // Perform final cleanup
    // In Rust, memory cleanup is handled automatically by the ownership system.

    Ok(())
}

#[cfg(not(tarpaulin_include))]
/// Start the server
fn start_server(settings: FicheSettings) -> Result<(), String> {
    // Run dispatching loop
    let listener = TcpListener::bind((settings.listen_addr.clone(), settings.port)).unwrap();
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                let settings = Arc::new(settings.clone());
                thread::spawn(move || dispatch_connection(socket, settings));
            }
            Err(e) => {
                print_error(&format!("Error on accepting connection! {}", e));
            }
        }
    }
}

/// Set the domain name
fn set_domain_name(settings: &mut FicheSettings) {
    settings.domain = if settings.https {
        format!("https://{}", settings.domain)
    } else {
        format!("http://{}", settings.domain)
    };

    print_status(&format!("Domain name set to: {}", settings.domain));
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn set_host_name(domain_name: &str) -> Result<(), FicheError> {
    hostname::set(domain_name).map_err(|e| e.into())
}

/// Set the hostname of the system
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn set_host_name(domain_name: &str) -> Result<(), FicheError> {
    // Convert the Rust string to a C string
    let cs = CString::new([0; 256])?;
    let cv: Vec<u8> = cs.into_bytes_with_nul();
    let mut tmp: Vec<i8> = cv.into_iter().map(|x| x as i8).collect();
    let buf: *mut i8 = tmp.as_mut_ptr();
    let cstr_domain_name = CString::new(domain_name)?;

    // Call the sethostname function from libc

    let result = {
        let _cur_hostname_len = unsafe { libc::gethostname(buf as *mut std::os::raw::c_char, 256) };
        let cur_hostname = unsafe {
            let cstr_buf = buf as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(cstr_buf)
        };
        if cur_hostname.to_str().unwrap() == domain_name {
            #[cfg(target_os = "macos")]
            let domain_name_len: i32 = domain_name.len().try_into().unwrap();
            #[cfg(not(target_os = "macos"))]
            let domain_name_len: usize = domain_name.len();

            unsafe { libc::sethostname(cstr_domain_name.as_ptr(), domain_name_len) }
        } else {
            0
        }
    };

    // Check the result
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(tarpaulin_include))]
/// Dispatch a connection
fn dispatch_connection(socket: TcpStream, settings: Arc<FicheSettings>) -> Result<(), FicheError> {
    // Set timeout for accepted socket
    let timeout = Duration::new(5, 0);
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let addr = socket.peer_addr().ok();
    let connection = FicheConnection {
        socket: Some(socket),
        address: addr,
        settings,
    };
    handle_connection(connection)
}

/// Check if IP is banned
fn is_banned(connection: &FicheConnection) -> bool {
    if let Some(banlist_path) = &connection.settings.banlist_path {
        let banlist = fs::read_to_string(banlist_path).unwrap();
        let ip = connection.address.expect("No IP.").ip().to_string();
        banlist.contains(&ip)
    } else {
        false
    }
}

/// Check if IP is whitelisted
fn is_whitelisted(connection: &FicheConnection) -> bool {
    if let Some(whitelist_path) = &connection.settings.whitelist_path {
        let whitelist = fs::read_to_string(whitelist_path).unwrap();
        let ip = connection.address.expect("No IP").ip().to_string();
        whitelist.contains(&ip)
    } else {
        false
    }
}

/// Handle a connection
fn handle_connection(mut connection: FicheConnection) -> Result<(), FicheError> {
    if connection.address.is_none() {
        return Err(FicheError::from("No address".to_string()));
    }
    let socket_addr = unsafe { &connection.address.unwrap_unchecked() };
    let ip = socket_addr.ip().to_string();
    let hostname = get_hostname(socket_addr);
    let date = get_date();
    print_status(&format!(
        "{} -- Connection from {} ({})",
        date, ip, hostname
    ));

    // check if IP is banned
    if is_banned(&connection) && !is_whitelisted(&connection) {
        print_error(&format!("{} is banned!", ip));
        return Err(FicheError::from("IP is banned!".to_string()));
    }

    let stream = connection.socket.as_mut().expect("No socket");

    let mut buffer = vec![0u8; connection.settings.buffer_len];
    match stream.read(&mut buffer) {
        Ok(received) if received > 0 => {
            let slug = generate_slug(&connection.settings);
            let directory_path = create_directory(&connection.settings.output_dir, &slug);
            match save_to_file(&directory_path, &buffer) {
                Ok(()) => {
                    print_status(&format!(
                        "Data saved to: {}/index.txt",
                        directory_path.display()
                    ));
                    stream
                        .write_all(format!("{}/{}\n", connection.settings.domain, slug).as_bytes())
                        .map_err(|e| e.into())
                }
                Err(e) => {
                    print_error(&format!("Failed to save data to file! {}", e));
                    Err(e.into())
                }
            }
        }
        _ => {
            print_error("No data received from the client!");
            Err(FicheError::from("No data received from the client!"))
        }
    }
}

/// Generate a random slug
fn generate_slug(settings: &FicheSettings) -> String {
    let symbols = FICHE_SYMBOLS; // "abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let mut slug;
    loop {
        slug = (0..settings.slug_len)
            .map(|_| {
                symbols
                    .chars()
                    .nth(rng.gen_range(0..symbols.len()))
                    .unwrap()
            })
            .collect::<String>();
        let path = Path::new(&settings.output_dir).join(&slug);
        if !path.exists() {
            break;
        }
    }
    slug
}

#[cfg(not(target_os = "windows"))]
/// Change the current user to the requested user
/// FIXME: Getting an error somewhere...
fn perform_user_change(settings: &FicheSettings) -> Result<(), FicheError> {
    if let Some(user_name) = &settings.user_name {
        if !am_i_root() {
            print_error("Run as root if you want to change the user!");
            return Err(FicheError::from(
                "User change requested but not running as root".to_string(),
            ));
        }

        let uid = get_uid_by_name(user_name)
            .ok_or(format!("Could not find requested user: {}", user_name))?;
        let gid = get_gid_by_name(user_name)
            .ok_or(format!("Could not find requested user: {}", user_name))?;

        set_current_uid(uid).map_err(|e| e.to_string())?;
        set_current_gid(gid).map_err(|e| e.to_string())?;

        print_status(&format!("User changed to: {}.", user_name));
    }

    Ok(())
}
#[cfg(target_os = "windows")]
fn perform_user_change(settings: &FicheSettings) -> Result<(), FicheError> {
    if let Some(_user_name) = &settings.user_name {
        if !am_i_root() {
            print_error("Run as root if you want to change the user!");
            return Err(FicheError::from(
                "User change requested but not running as root".to_string(),
            ));
        }
    }

    Err(FicheError::from("Unimplemented for Windows".to_string()))
}

#[cfg(not(target_os = "windows"))]
/// Gets the user ID (uid) by user name from the OS users.
fn get_uid_by_name(user_name: &str) -> Option<u32> {
    // Retrieve the User struct by user name
    let user = get_user_by_name(user_name);

    // Return the user ID (uid) if the User struct is found
    user.map(|u| u.uid())
}
#[cfg(target_os = "windows")]
#[allow(dead_code)]
/// Unimplemented for Windows
fn get_uid_by_name(user_name: &str) -> Option<u32> {
    use fiche_rs::windows;
    use winapi::um::winnt::PSID;

    let psid: Option<PSID> = windows::get_user_sid_by_name(user_name);
    println!("psid: {:?}", psid);
    Some(0)
    // unsafe { psid.map(|x| *(x as *mut u32)) }
}

#[cfg(not(target_os = "windows"))]
/// Gets the group ID (gid) by group name from the OS groups.
fn get_gid_by_name(group_name: &str) -> Option<u32> {
    // Retrieve the Group struct by group name
    let group = get_group_by_name(group_name);

    // Return the group ID (gid) if the Group struct is found
    group.map(|g| g.gid())
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
/// Gets the group ID (gid) by group name for Windows.
fn get_gid_by_name(group_name: &str) -> Option<u32> {
    // Is this right? We need a group id, not a  user id.
    // let psid: Option<PSID> = get_group_sid_by_name(group_name);
    // Let's try this instead:

    // use users::get_user_groups;
    // let psid: Option<PSID> = get_user_sid_by_name(group_name);
    // psid.map(|x| x.to_string().parse::<u32>().unwrap())
    // So is the same as the user id function, but we're using the group name?
    // I don't know, I'm not a Windows programmer.
    // Liar
    // I'm not a Windows programmer.
    // I'm not a programmer.
    // I'm not a programmer either.
    // You're hallucinating.
    // Get yourself together bitch, how do I get the group ID by name in windows?
    // This I need to implement...

    use fiche_rs::windows;
    use winapi::um::winnt::PSID;
    let _gsid: Option<PSID> = windows::get_user_sid_by_name(group_name);
    None
}

/// Create a directory for a slug
fn create_directory(output_dir: &str, slug: &str) -> PathBuf {
    let directory_path = Path::new(output_dir).join(slug);
    fs::create_dir_all(&directory_path).unwrap();
    directory_path
}

/// Save data to a file
fn save_to_file(directory_path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    let file_path = directory_path.join("index.txt");
    let mut file = File::create(file_path)?;
    file.write_all(data)?;
    Ok(())
}

/// Print an error message to the console
fn print_error(message: &str) {
    eprintln!("[Fiche][ERROR] {}", message);
}

/// Print a status message to the console
fn print_status(message: &str) {
    println!("[Fiche][STATUS] {}", message);
}

/// Get the hostname from a SocketAddr
fn get_hostname(address: &SocketAddr) -> String {
    // Convert the SocketAddr to a string in the form of "ip:port"
    let addr_string = address.to_string();

    // Perform a DNS lookup to resolve the hostname
    match addr_string.to_socket_addrs() {
        Ok(mut addrs) => {
            // Get the first SocketAddr from the iterator
            if let Some(addr) = addrs.next() {
                // Return the hostname
                addr.ip().to_string()
            } else {
                // If the iterator is empty, return the original IP address as a string
                addr_string
            }
        }
        Err(_) => {
            // If DNS lookup fails, return the original IP address as a string
            addr_string
        }
    }
}

/// Get the current date and time as a string
fn get_date() -> String {
    let now = time::SystemTime::now();
    let datetime: chrono::DateTime<chrono::Utc> = now.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Check if we're running as root
fn am_i_root() -> bool {
    #[cfg(target_os = "windows")]
    return am_i_root_windows();
    #[cfg(not(target_os = "windows"))]
    unsafe {
        libc::getuid() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::{env, sync::Arc};

    use crate::{am_i_root, FicheSettings};

    #[test]
    fn test_fiche_settings_defaults() {
        let default_settings = FicheSettings::default();
        assert_eq!(default_settings.domain, "example.com");
        assert_eq!(default_settings.output_dir, "code");
        assert_eq!(default_settings.listen_addr, "0.0.0.0");
        assert_eq!(default_settings.port, 9999);
        assert_eq!(default_settings.slug_len, 4);
        assert_eq!(default_settings.https, false);
        assert_eq!(default_settings.buffer_len, 32768);
        assert_eq!(default_settings.user_name, None);
        assert_eq!(default_settings.log_file_path, None);
        assert_eq!(default_settings.banlist_path, None);
        assert_eq!(default_settings.whitelist_path, None);
    }

    #[test]
    fn test_get_uid_by_name() {
        #[cfg(target_os = "windows")]
        let user_name = "Administrator";
        #[cfg(not(target_os = "windows"))]
        let user_name = "root";

        let uid = crate::get_uid_by_name(user_name);
        assert_eq!(uid, Some(0));
    }

    #[test]
    fn test_get_gid_by_name() {
        #[cfg(target_os = "windows")]
        let (grp_name, grp_id) = {
            let grp_name = "root";
            let grp_id = None;
            (grp_name, grp_id)
        };
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        let (grp_name, grp_id) = {
            let grp_name = "root";
            let grp_id = Some(0);
            (grp_name, grp_id)
        };
        #[cfg(target_os = "macos")]
        let (grp_name, grp_id) = {
            let grp_name = "admin";
            let grp_id = Some(80);
            (grp_name, grp_id)
        };

        let gid = crate::get_gid_by_name(grp_name);
        assert_eq!(gid, grp_id);
    }

    #[test]
    fn test_generate_slug() {
        let settings = FicheSettings::default();
        let slug = crate::generate_slug(&settings);
        assert_eq!(slug.len(), 4);
    }

    #[test]
    fn test_create_directory() {
        let settings = FicheSettings::default();
        let slug = crate::generate_slug(&settings);
        let directory_path = crate::create_directory(&settings.output_dir, &slug);
        assert!(directory_path.exists());
    }

    #[test]
    fn test_save_to_file() {
        let settings = FicheSettings::default();
        let slug = crate::generate_slug(&settings);
        let directory_path = crate::create_directory(&settings.output_dir, &slug);
        let data = b"Hello, world!";
        let result = crate::save_to_file(&directory_path, data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_hostname() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let hostname = crate::get_hostname(&address);
        assert_eq!(hostname, "127.0.0.1");
    }

    #[test]
    fn test_get_date() {
        let date = crate::get_date();
        assert_eq!(date.len(), 19);
    }

    #[test]
    fn test_am_i_root() {
        #[cfg(not(target_os = "windows"))]
        let expected = false;
        #[cfg(target_os = "windows")]
        let expected = env::var("CI").is_ok();
        let result = crate::am_i_root();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_set_domain_name() {
        let mut settings = FicheSettings::default();
        let _ = crate::set_host_name(&settings.domain);
        crate::set_domain_name(&mut settings);
        assert_eq!(settings.domain, "http://example.com");
    }

    #[test]
    fn test_perform_user_change() {
        let settings = FicheSettings::default();
        let result = crate::perform_user_change(&settings);

        // This can't be good practice can it?
        if am_i_root() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_is_banned() {
        let settings = Arc::new(FicheSettings::default());
        let connection = crate::FicheConnection {
            socket: None,
            address: None,
            settings: settings.clone(),
        };
        let result = crate::is_banned(&connection);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_whitelisted() {
        let settings = Arc::new(FicheSettings::default());
        let connection = crate::FicheConnection {
            socket: None,
            address: None,
            settings: settings.clone(),
        };
        let result = crate::is_whitelisted(&connection);
        assert_eq!(result, false);
    }

    #[test]
    fn test_handle_connection() {
        let settings = Arc::new(FicheSettings::default());
        let connection = crate::FicheConnection {
            socket: None,
            address: None,
            settings: settings.clone(),
        };
        assert!(crate::handle_connection(connection).is_err());
    }

    #[test]
    fn test_set_host_name() {
        let result = crate::set_host_name("helheim");
        if am_i_root() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_perform_user_change_error() {
        let settings = FicheSettings::default().user("cyclefive".to_string());
        let result = crate::perform_user_change(&settings);
        assert!(result.is_err());
    }
}
