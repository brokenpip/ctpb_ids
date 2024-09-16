use core::time;
use std::{fs, thread};
use std::path::Path;
use std::process::{self};
use std::fs::{File, OpenOptions};
use std::process::Command;
use std::io::Write;


fn main() {
    println!("Hello, world!");

    let tick = time::Duration::from_millis(1000);
    let debug = false;
    let target_pid = process::id();
    let lock_path = format!("/var/chromia/tpm/{}",target_pid.to_string());
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

    let tpm_folder_p = "/var/chromia/tpm";
    let fpath = Path::new(tpm_folder_p);
    if !fpath.exists() {
        // Create the folder
        let _ = fs::create_dir(fpath);
        println!("Folder created successfully!");
    } else {
        println!("Folder already exists.");
    }
 
    
    // confirm hash of IDS code
   
    let ids_path = "/home/ids/Documents/GitHub/ctpb_ids/ctpb_tpm/Cargo.toml";

    let (bbo, exec_hash) = genhash(&ids_path);
    if bbo {
        println!("Hash: {}", exec_hash);
    }

    // create encrypted log file and stream changes to normal and enc variant 
    // NEED log file code from IDS
    
    let num_iterations = 10;
    let mut i= 0;


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
            let trouble_path = format!("/var/chromia/tpm/{}",lcb.to_string());
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
        Ok(_) => {
            let logi = format!("File '{}' deleted successfully.", lock_path);
            let _ = append_to_log(&logi);
        }
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
    let lock_name = directory_read("/var/chromia/tpm").unwrap_or_else(|| "aa".to_string());
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
        .output() {
        
        Ok(output) => output,
        Err(err) => {
            eprintln!("Failed to execute command for key '{}': {}", key, err);
            return (false, String::new());
        }
    };
    // Convert output to string
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();
    
    //println!("{}", stdout_str);

    if !stderr_str.is_empty() {
        eprintln!("stderr for key '{}': {}", key, stderr_str);
    }

    (true, stdout_str)
}

fn append_to_log(message: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)  // This will create the file if it doesn't exist
        .open("TPM.log")?;

    writeln!(file, "{}", message)?;  // Write the message and append a newline
    Ok(())
}