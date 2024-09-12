use core::time;
use std::{fs, thread};
use std::path::Path;
use std::process::{self};
use std::fs::File;

fn main() {
    println!("Hello, world!");

    let tick = time::Duration::from_millis(1000);
    let debug = false;
    let target_pid = process::id();
    let lock_path = format!("/tmp/tpm/{}",target_pid.to_string());
    println!("{}",lock_path.to_string()); //debug use

    // 1 - see if any remnants exist
    let (lca, lcb) = lock_check(&target_pid);

    if !lca {
        println!("Previous shutdown improper!! ID of {} was found", lcb);
    } else {
        let _ = File::create(&lock_path);
        if file_check(&lock_path) {
            println!("Lock file created.") // to log
        }
    }
    println!("{}",debug);

    //establish link to IDS


    
    //confirm hash of IDS code


    //create encrypted log file and stream changes to normal and enc variant 

    
    let num_iterations = 10;
    let mut i= 0;
    //let _ = File::create(&lock_path);

    loop {
        //rate limiter
        thread::sleep(tick);
        if i >= num_iterations {
            break;
        }
        i += 1;

        //self-check
        let (lca, lcb) = lock_check(&target_pid);
        if !lca {
            println!("TPM tampered with; ID of {} was found", lcb);
            let trouble_path = format!("/tmp/tpm/{}",lcb.to_string());
            match fs::remove_file(&trouble_path) {
                Ok(_) => println!("File '{}' deleted successfully.", &lock_path),
                Err(e) => println!("Failed to delete file '{}': {}", &lock_path, e),
            }
        }
        if lca && lcb == 0 {
            println!("TPM tampered with; lock_file deleted");
            let _ = File::create(&lock_path);
            if file_check(&lock_path) {
                println!("Lock file created.") // to log
            }
        }

        
    }
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