use core::time;
use std::{fs, thread};
use std::path::Path;
use std::process;
use std::fs::File;

fn main() {
    println!("Hello, world!");

    let tick = time::Duration::from_millis(1000);
    let debug = false;
    let target_pid = process::id();
    let lock_path = format!("/tmp/tpm`{}",target_pid.to_string());

    let lock_name = directory_read("/tmp/tpm").unwrap_or_else(|| "aa".to_string());
    let lock_pid: u32 = lock_name.parse().unwrap_or(0);

    if lock_pid != target_pid {
        println!("Previous shutdown improper!!");
    } else if lock_pid == target_pid {
        println!("GOOD!");
    } else {
        
        if debug {
            println!("Nothing generated, error.");
        }
    }

    let _ = File::create(&lock_path);

    loop {
        thread::sleep(tick)
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