use rand::Rng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{self, Duration};
use users::switch::{set_current_gid, set_current_uid};
use users::{get_group_by_name, get_user_by_name};

// Define constants
const FICHE_SYMBOLS: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

use clap::Parser;

// Define the FicheSettings struct
#[derive(Clone, Debug)]
struct FicheSettings {
    domain: String,
    output_dir: String,
    listen_addr: String,
    port: u16,
    slug_len: usize,
    https: bool,
    buffer_len: usize,
    user_name: Option<String>,
    log_file_path: Option<String>,
    banlist_path: Option<String>,
    whitelist_path: Option<String>,
}

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

impl FicheSettings {
    fn new(args: &Args) -> Self {
        let mut settings = FicheSettings::default();
        settings.domain = args.domain.clone();
        settings.output_dir = args.output_directory.clone();
        settings.listen_addr = args.listen.clone();
        settings.port = args.port;
        settings.slug_len = args.slug_length;
        settings.https = args.ssl;
        settings.buffer_len = args.buffer_length;
        settings.user_name = args.user.clone();
        settings.log_file_path = args.log.clone();
        settings.banlist_path = args.banlist.clone();
        settings.whitelist_path = args.whitelist.clone();
        settings
    }
}

struct FicheConnection {
    socket: TcpStream,
    address: SocketAddr,
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

fn main() -> Result<(), String> {
    // Define the command-line interface using the clap crate

    // Parse the command-line arguments
    let args = Args::parse();

    let settings = FicheSettings::new(&args);
    fiche_run(settings)
}

// Continue with the equivalent Rust implementation of fiche_run function
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

fn start_server(settings: FicheSettings) -> Result<(), String> {
    // ... (Implementation of the fiche_run function)
    // Run dispatching loop
    let listener = TcpListener::bind((settings.listen_addr.clone(), settings.port)).unwrap();
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                let settings = Arc::new(settings.clone());
                thread::spawn(move || {
                    dispatch_connection(socket, settings);
                });
            }
            Err(e) => {
                print_error(&format!("Error on accepting connection! {}", e));
            }
        }
    }
}

fn set_domain_name(settings: &mut FicheSettings) {
    settings.domain = if settings.https {
        format!("https://{}", settings.domain)
    } else {
        format!("http://{}", settings.domain)
    };

    print_status(&format!("Domain name set to: {}", settings.domain));
}
// fn set_domain_name(domain_name: &str) -> Result<(), Error> {
//     // Convert the Rust string to a C string
//     let cstr_domain_name = CString::new(domain_name)?;

//     // Call the sethostname function from libc
//     let result = unsafe { libc::sethostname(cstr_domain_name.as_ptr(), domain_name.len()) };

//     // Check the result
//     if result == 0 {
//         Ok(())
//     } else {
//         Err(Error::last_os_error())
//     }
// }

fn dispatch_connection(socket: TcpStream, settings: Arc<FicheSettings>) {
    // Set timeout for accepted socket
    let timeout = Duration::new(5, 0);
    socket.set_read_timeout(Some(timeout)).unwrap();
    socket.set_write_timeout(Some(timeout)).unwrap();
    let addr = socket.peer_addr().unwrap();
    let connection = FicheConnection {
        socket,
        address: addr,
        settings,
    };
    handle_connection(connection);
}

fn is_banned(connection: &FicheConnection) -> bool {
    if let Some(banlist_path) = &connection.settings.banlist_path {
        let banlist = fs::read_to_string(banlist_path).unwrap();
        let ip = connection.address.ip().to_string();
        banlist.contains(&ip)
    } else {
        false
    }
}

fn is_whitelisted(connection: &FicheConnection) -> bool {
    if let Some(whitelist_path) = &connection.settings.whitelist_path {
        let whitelist = fs::read_to_string(whitelist_path).unwrap();
        let ip = connection.address.ip().to_string();
        whitelist.contains(&ip)
    } else {
        false
    }
}

fn handle_connection(mut connection: FicheConnection) {
    // ... (Implementation of the handle_connection function)
    let ip = connection.address.ip().to_string();
    let hostname = get_hostname(&connection.address);
    let date = get_date();
    print_status(&format!(
        "{} -- Connection from {} ({})",
        date, ip, hostname
    ));

    // check if IP is banned
    if is_banned(&connection) && !is_whitelisted(&connection) {
        print_error(&format!("{} is banned!", ip));
        return;
    }

    let mut buffer = vec![0u8; connection.settings.buffer_len];
    match connection.socket.read(&mut buffer) {
        Ok(received) if received > 0 => {
            let slug = generate_slug(&connection.settings);
            let directory_path = create_directory(&connection.settings.output_dir, &slug);
            match save_to_file(&directory_path, &buffer) {
                Ok(()) => {
                    print_status(&format!(
                        "Data saved to: {}/index.txt",
                        directory_path.display()
                    ));
                    connection
                        .socket
                        .write_all(format!("{}/{}\n", connection.settings.domain, slug).as_bytes())
                        .unwrap();
                }
                Err(e) => {
                    print_error(&format!("Failed to save data to file! {}", e));
                }
            }
        }
        _ => {
            print_error("No data received from the client!");
        }
    }
}

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

/// Change the current user to the requested user
/// FIXME: Getting an error somewhere...
fn perform_user_change(settings: &FicheSettings) -> Result<(), String> {
    if let Some(user_name) = &settings.user_name {
        if !am_i_root() {
            print_error("Run as root if you want to change the user!");
            return Err("User change requested but not running as root".to_string());
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
fn get_uid_by_name(user_name: &str) -> Option<u32> {
    // Retrieve the User struct by user name
    let user = get_user_by_name(user_name);

    // Return the user ID (uid) if the User struct is found
    user.map(|u| u.uid())
}

fn get_gid_by_name(group_name: &str) -> Option<u32> {
    // Retrieve the Group struct by group name
    let group = get_group_by_name(group_name);

    // Return the group ID (gid) if the Group struct is found
    group.map(|g| g.gid())
}
fn create_directory(output_dir: &str, slug: &str) -> PathBuf {
    let directory_path = Path::new(output_dir).join(slug);
    fs::create_dir_all(&directory_path).unwrap();
    directory_path
}

fn save_to_file(directory_path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    let file_path = directory_path.join("index.txt");
    let mut file = File::create(file_path)?;
    file.write_all(data)?;
    Ok(())
}

fn print_error(message: &str) {
    eprintln!("[Fiche][ERROR] {}", message);
}

fn print_status(message: &str) {
    println!("[Fiche][STATUS] {}", message);
}

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

fn get_date() -> String {
    let now = time::SystemTime::now();
    let datetime: chrono::DateTime<chrono::Utc> = now.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn am_i_root() -> bool {
    unsafe { libc::getuid() == 0 }
}
