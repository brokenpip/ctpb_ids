use core::time;
use std::{fs, thread};
use std::path::Path;
use std::process::{self, Command};
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use nix::fcntl::{fcntl, FcntlArg};
use nix::libc::{SEEK_SET as libc_seek_set, flock as libc_flock};

const F_WRLCK: i16 = 1;
const SEEK_SET: i16 = libc_seek_set as i16;

fn main() {
    println!("Hello, world!");

    let tick = time::Duration::from_millis(1000);
    let debug = false;
    let target_pid = process::id();
    let lock_path = format!("/tmp/tpm/{}", target_pid.to_string());
    println!("{}", lock_path.to_string()); // debug use

    // 1 - see if any remnants exist
    let (lca, lcb) = lock_check(&target_pid);

    if !lca {
        println!("Previous shutdown improper!! ID of {} was found", lcb);
    } else {
        let _ = File::create(&lock_path); 
        // Create the lock file if it does not exist
        if file_check(&lock_path) {
            println!("Lock file created.");
            let file_to_lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path);

            if let Ok(file) = file_to_lock {
                println!("Lockign file.");
                let filedd = file.as_raw_fd();

                let w_lock = libc_flock {
                    l_type: F_WRLCK,
                    l_whence: SEEK_SET,
                    l_start: 0,
                    l_len: 0,
                    l_pid: 0,
                };
                

                match fcntl(filedd, FcntlArg::F_SETLK(&w_lock)) {
                    Ok(_) => {
                        println!("Write lock acquired");
                        // establish link to IDS

                        // set for future use

                        // confirm hash of IDS code
                        let ids_path = "/home/ids/Documents/GitHub/ctpb_ids/ctpb_tpm/Cargo.toml";

                        let (bbo, exec_hash) = genhash(&ids_path);
                        if bbo {
                            println!("Hash: {}", exec_hash);
                        }

                        // create encrypted log file and stream changes to normal and enc variant 
                        // NEED log file code from IDS
                        
                        let num_iterations = 100;
                        let mut i = 0;

                        loop {
                            // rate limiter
                            thread::sleep(tick);
                            if i >= num_iterations {
                                break;
                            }
                            i += 1;

                            // self-check
                            let (lca, lcb) = lock_check(&target_pid);
                            if !lca {
                                println!("TPM tampered with; ID of {} was found", lcb);
                                let trouble_path = format!("/tmp/tpm/{}", lcb.to_string());
                                match fs::remove_file(&trouble_path) {
                                    Ok(_) => println!("File '{}' deleted successfully.", &lock_path),
                                    Err(e) => println!("Failed to delete file '{}': {}", &lock_path, e),
                                }
                            }
                            if lca && lcb == 0 {
                                println!("TPM tampered with; lock_file deleted");
                                let _ = File::create(&lock_path); // ignore result
                                if file_check(&lock_path) {
                                    println!("Lock file created.") // to log
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("Error acquiring write lock: {}", e),
                }
            } else {
                eprintln!("Error opening file for locking");
            }
        }
    }
    println!("{}", debug);

    

    match fs::remove_file(&lock_path) {
        Ok(_) => println!("File '{}' deleted successfully.", &lock_path),
        Err(e) => println!("Failed to delete file '{}': {}", &lock_path, e),
    }
}

/*
1. create file and lock based on process id of executing process
1a. if file already exists with diff process ID, raise alert
2. compare hash of a file to an unencrypted reference (to begin, to be encrypted)
3. pipe between IDS and TPM is established, all logs are sent along to be stored in a bkp log file
4. create log file for each run and verify against stored hashes for previous file in chain
5. chain changes are entered into another file for encrypted storage (start as unencrypted)
6. 
*/

fn lock_check(target_pid: &u32) -> (bool, u32) {
    let lock_name = directory_read("/tmp/tpm").unwrap_or_else(|| "aa".to_string());
    let lock_pid: u32 = lock_name.parse().unwrap_or(0);
    if lock_pid == 0 {
        return (true, 0);
    } else if lock_pid == *target_pid {
        return (true, *target_pid);
    } else {
        return (false, lock_pid);
    }
}

fn file_check(path: &str) -> bool {
    Path::new(path).exists()
}

fn directory_read(path: &str) -> Option<String> {
    let entries = fs::read_dir(path).ok()?;

    if let Some(entry) = entries.into_iter().next() {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.is_file() {
            if let Some(name_str) = path.file_name().and_then(|name| name.to_str()) {
                return Some(name_str.to_string());
            }
        }
    }

    None
}

fn genhash(key: &str) -> (bool, String) {
    let output = match Command::new("b3sum")
        .arg(key)
        .arg("--no-names")
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            eprintln!("Failed to execute command for key '{}': {}", key, err);
            return (false, String::new());
        }
    };

    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();

    if !stderr_str.is_empty() {
        eprintln!("stderr for key '{}': {}", key, stderr_str);
    }

    (true, stdout_str)
}
