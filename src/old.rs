/*
Fiche - Command line pastebin for sharing terminal output.

-------------------------------------------------------------------------------

License: MIT (http://www.opensource.org/licenses/mit-license.php)
Repository: https://github.com/solusipse/fiche/
Live example: http://termbin.com

-------------------------------------------------------------------------------

usage: fiche [-DepbsdolBuw].
             [-D] [-e] [-d domain] [-p port] [-s slug size]
             [-o output directory] [-B buffer size] [-u user name]
             [-l log file] [-b banlist] [-w whitelist]

Use netcat to push text - example:
$ cat fiche.c | nc localhost 9999

-------------------------------------------------------------------------------
*/

// #ifndef FICHE_H
// #define FICHE_H

// #include <stdint.h>
// #include <stdbool.h>

use std::time::SystemTime;

use chrono::Utc;

/**
 * @brief Used as a container for fiche settings. Create before
 *        the initialization
 *
 */
struct FicheSettings {
    /**
     * @brief Domain used in output links
     */
    domain: String,

    /**
     * @brief Path to directory used for storing uploaded pastes
     */
    output_dir_path: String,

    /**
     * @brief Address on which fiche is waiting for connections
     */
    listen_addr: String,

    /**
     * @brief Port on which fiche is waiting for connections
     */
    port: u16,

    /**
     * @brief Length of a paste's name
     */
    slug_len: u8,

    /**
     * @brief If set, returns url with https prefix instead of http
     */
    https: bool,

    /**
     * @brief Connection buffer length
     *
     * @remarks Length of this buffer limits max size of uploaded files
     */
    buffer_len: u32,

    /**
     * @brief Name of the user that runs fiche process
     */
    user_name: String,

    /**
     * @brief Path to the log file
     */
    log_file_path: String,

    /**
     * @brief Path to the file with banned IPs
     */
    banlist_path: String,

    /**
     * @brief Path to the file with whitelisted IPs
     */
    whirelist_path: String,
}

impl Default for FicheSettings {
    fn default() -> FicheSettings {
        FicheSettings {
            domain: String::from("example.com"),
            output_dir_path: String::from("code"),
            listen_addr: String::from("0.0.0.0"),
            port: 9999,
            slug_len: 4,
            https: false,
            buffer_len: 32768,
            user_name: String::from(""),
            log_file_path: String::from(""),
            banlist_path: String::from(""),
            whirelist_path: String::from(""),
        }
    }
}

/**
 *  @brief Runs fiche server
 *
 *  @return 0 if it was able to start, any other value otherwise
 */
//int fiche_run(Fiche_Settings settings);
fn fiche_run(settings: FicheSettings) -> i32 {
    // set seed to time null
    let seed = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // get current date as string
    let date = Utc::now();

    println!("Starting fiche server on {}....", date);
    return 0;
}

/**
 * @brief array of symbols used in slug generation
 * @remarks defined in fiche.c
 */
//extern const char *Fiche_Symbols;

fn main() {
    println!("Hello, world!");
}
