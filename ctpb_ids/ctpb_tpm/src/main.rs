use core::time;
use std::{fs, thread};
use std::path::Path;
use std::process::{self};
use std::fs::{File, OpenOptions};
use std::process::{Command,Stdio};
use std::io::Write;
use std::str;
use std::io;


fn main() {
    println!("Hello, world!");
    
    let tpm_folder_a = "/var/chromia";
    let tpm_folder_p = "/var/chromia/tpm";
    let _ = append_to_log(&tpm_folder_a);
    let fpath = Path::new(tpm_folder_a);
    if !fpath.exists() {
        // Create the folder
        match fs::create_dir(fpath) {
            Ok(_) => {
                append_to_log(&format!("Directory created successfully."));
                let fpath2 = Path::new(tpm_folder_p);
                match fs::create_dir(fpath2) {
                    Ok(_) => {
                        append_to_log(&format!("Directory created successfully."));
                    }
                    Err(e) => append_to_log(&format!("Failed to create directory: {}", e)),
                }
            }
            Err(e) => append_to_log(&format!("Failed to create directory: {}", e)),
        }
    } else {
        println!("Folder already exists.");
        let fpath = Path::new(tpm_folder_p);
        if !fpath.exists() {
            // Create the folder
            match fs::create_dir(fpath) {
                Ok(_) => {
                    append_to_log(&format!("Directory created successfully."));
                    let fpath2 = Path::new(tpm_folder_p);
                    match fs::create_dir(fpath2) {
                        Ok(_) => {
                            append_to_log(&format!("Directory created successfully."));
                        }
                        Err(e) => append_to_log(&format!("Failed to create directory: {}", e)),
                    }
                }
                Err(e) => append_to_log(&format!("Failed to create directory: {}", e)),
            }
        } else {
            append_to_log(&format!("Folder already exists."));
            
        }
    }

    let tick = time::Duration::from_millis(1000);
    let debug = false;
    let target_pid = process::id();
    let lock_path = format!("/var/chromia/tpm/{}",target_pid.to_string());
    append_to_log(&format!("{}",lock_path.to_string())); //debug use

    // 1 - see if any remnants exist
    let (lca, lcb) = lock_check(&target_pid);

    if !lca {
        append_to_log(&format!("Previous shutdown improper!! ID of {} was found", lcb));
    } else {
        let _ = File::create(&lock_path);
        if file_check(&lock_path) {
            append_to_log(&format!("Lock file created.")) // to log
        }
    }
    append_to_log(&format!("{}",debug));

    
 
    
    // confirm hash of IDS code
   
    let ids_path = "/bin/Chromia/Chromia";

    let (bbo, exec_hash) = genhash(&ids_path);
    if bbo {
        append_to_log(&format!("Hash: '{}'", exec_hash.trim()));
        if exec_hash.trim() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262".to_string() {
            append_to_log(&format!("No tamper found for IDS."));
        } else {
            append_to_log(&format!("Hash for IDS not matching."));
        }
    }

    // create encrypted log file and stream changes to normal and enc variant 
    // NEED log file code from IDS
    
    let num_iterations = 100;
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
            append_to_log(&format!("TPM tampered with; ID of {} was found", lcb));
            let trouble_path = format!("/var/chromia/tpm/{}",lcb.to_string());
            match fs::remove_file(&trouble_path) {
                Ok(_) => append_to_log(&format!("File '{}' deleted successfully.", &lock_path)),
                Err(e) => append_to_log(&format!("Failed to delete file '{}': {}", &lock_path, e)),
            }
        }
        if lca && lcb == 0 {
            append_to_log(&format!("TPM tampered with; lock_file deleted"));
            let _ = File::create(&lock_path);
            if file_check(&lock_path) {
                append_to_log(&format!("Lock file created.")); // to log
            }
        }

        //get IDS PID
        

        //ids check
        let fpid = find_single_pid_by_command("./emulate");
        //println!("fpid was {}", &fpid);
        if fpid != 0 {
            let lcc = ids_check(&fpid);
            if lcc {
                //println!("IDS as expected.") //debug
            } else {
                append_to_log(&format!("IDS not as expected. Suspected impersonation!!"));
            }
        } else {
            append_to_log(&format!("IDS not found, starting IDS"));
            //Code to start IDS program; need either systemd linkage or path to binary
            let _ = start_ids();
        }

        
    }
    match fs::remove_file(&lock_path) {
        Ok(_) => {
            let logi = format!("File '{}' deleted successfully.", lock_path);
            let _ = append_to_log(&logi);
        }
        Err(e) => {append_to_log(&format!("Failed to delete file '{}': {}", &lock_path, e));}
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

fn start_ids() -> io::Result<()> {
    let output = Command::new("sudo")
        .arg("systemctl")
        .arg("restart")
        .arg("Chromia")
        .output()?;

    if output.status.success() {
        append_to_log(&format!("IDS started successfully."));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        append_to_log(&format!("Failed to start IDS: {}", error_message));
    }
    
    Ok(())
}

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

fn ids_check(target_pid: &u32) -> bool {
    let lock_name = directory_read("/var/chromia/ids").unwrap_or_else(|| "aa".to_string());
    let lock_pid: u32 = lock_name.parse().unwrap_or(0);

    let (bbo, pid_result) = match_pid(&lock_pid.to_string());
    //println!("match pid result DEBUG ONLY was {}{}", bbo,&pid_result.trim());
    /*if pid_result.trim() == "./emulate" {
        println!("trueay");
    } */
    if bbo && pid_result.trim() == "./emulate" {
        if lock_pid == *target_pid {
            return true;
        } else {
            append_to_log(&format!("Found process from lock folder but did not match target."));
            return false;
        }
    } else {
        append_to_log(&format!("No process match from lock folder, target PID was {}", target_pid));
        return false;
    }
}

fn match_pid(key: &str) -> (bool, String) {
    if !key.chars().all(char::is_numeric) {
        append_to_log(&format!("Invalid PID: '{}'", key));
        return (false, String::new());
    }

    let output = match Command::new("ps")
        .arg("-q")
        .arg(key)
        .arg("-o")
        .arg("cmd=")
        .output() {
        
        Ok(output) => output,
        Err(err) => {
            append_to_log(&format!("Failed to execute command for key '{}': {}", key, err));
            return (false, String::new());
        }
    };
    // Convert output to string
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();
    //println!("mpid out was {}", &stdout_str);
    //println!("{}", stdout_str);

    if !stderr_str.is_empty() {
        append_to_log(&format!("stderr for key '{}': {}", key, stderr_str));
    }

    (true, stdout_str)
}


fn find_single_pid_by_command(cmd: &str) -> u32 {
    
    let pgrep_output = Command::new("pgrep")
    .arg("-f") // Match against the full command line
    .arg(cmd)
    .stdout(Stdio::piped()) // Pipe the output
    .output(); // Capture the output

    // Use match to handle the Result without terminating
    let pgrep_output = match pgrep_output {
        Ok(output) => output,
        Err(_) => return 0, // Return 0 if the command fails
    };

    // Create a longer-lived variable for the output
    let output_str = String::from_utf8_lossy(&pgrep_output.stdout);
    let last_line = output_str.lines().last().unwrap_or(""); // Handle case with no output
    //println!("{:?}", &last_line);

    // Attempt to parse and return the PID, returning 0 on failure
    last_line.trim().parse::<u32>().unwrap_or(0)
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
    let output = match Command::new("/bin/Chromia/Data/b3sum")
        .arg(key)
        .arg("--no-names")
        .output() {
        
        Ok(output) => output,
        Err(err) => {
            append_to_log(&format!("Failed to execute command for key '{}': {}", key, err));
            return (false, String::new());
        }
    };
    // Convert output to string
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();
    
    //println!("{}", stdout_str);

    if !stderr_str.is_empty() {
        append_to_log(&format!("stderr for key '{}': {}", key, stderr_str));
    }

    (true, stdout_str)
}

fn append_to_log(message: &str) {
    println!("{}",&message);
    // Try to open the file
    let _ = OpenOptions::new()
        
        .write(true)
        .append(true)
        .create(true)
        .open("/var/log/ironhide.log")
        .map(|mut file| {
            // Try to write the message
            let _ = writeln!(file, "{}", message);
        });
}
