use std::time::Duration;
use std::thread;
use std::fs::OpenOptions;
use std::process::Command;
use std::io::Write;
use std::str;
use std::io;
use std::fs;
use std::path::Path;



fn main() {
    println!("Hello, world!");
    // confirm hash of IDS code
   
    let ids_path = "/bin/Chromia/Chromia";

    let (bbo, exec_hash) = genhash(&ids_path);
    if bbo {
        append_to_log(&format!("Hash: '{}'", exec_hash.trim()));
        if exec_hash.trim() == "80151b0cc10f937dabcda74a68557f32437a59838216b1f3eabe0bd02ef3b4c2".to_string() {
            append_to_log(&format!("No tamper found for IDS."));
        } else {
            append_to_log(&format!("Hash for IDS not matching."));
        }
    }

    // create encrypted log file and stream changes to normal and enc variant 
    // NEED log file code from IDS
    
    let num_iterations = 100;
    let mut i= 0;
    let mut info_counter = 0;


    loop {
        //rate limiter
        thread::sleep(Duration::from_millis(5000));
        if i >= num_iterations {
            break;
        }
        i += 1;

        //check IDS binary is correct
        let bintpm_path = "/bin/Chromia/Chromia";
        let (bbo, exec_hash) = genhash(&bintpm_path);
        if bbo {
            //let message = format!("[DEBUG] IDS Hash: '{}'", exec_hash.trim());
            //append_to_log(&message);
            
            if exec_hash.trim() == "90e864b5d26e7ca64031f1435b4c7de034abfa9266558061e009bdae6d318c3a".to_string() {
                info_counter += 1; // Increment the info counter
                if info_counter >= 100 {
                    append_to_log("[Info] No tamper found for IDS.");
                    info_counter = 0; // Reset the counter
                }
            } else {
                append_to_log("[Serious] Hash for IDS not matching.");
                match reinstall_ids() {
                    Ok(()) => println!("Binary cloned and moved successfully!"),
                    Err(e) => eprintln!("Error: {}", e),
                }
                println!("Marker.");
                if let Err(e) = reinstall_ids() {
                    append_to_log(&format!("[INTERNAL ERROR]: {}", e));
                } else {
                    append_to_log("[Info] IDS Installation completed successfully!");
                }
            }
        } else {
            append_to_log("[Warning] Unable to hash IDS binary.");
        }
        

        //check IDS is running
        let service_name = "Chromia.service";
        match is_service_running(service_name) {
            Ok(true) => {
                info_counter += 1; // Increment the info counter
                if info_counter >= 100 {
                    append_to_log(&format!("[Info] '{}' is running.", service_name));
                    info_counter = 0; // Reset the counter
                }
            }
            Ok(false) => {
                append_to_log(&format!("[CRITICAL] '{}' is not running.", service_name));
                let _ = start_ids();
            }
            Err(e) => append_to_log(&format!("[INTERNAL ERROR] Error checking status: {}", e)),
        }
    }
        
}
    


fn start_ids() -> io::Result<()> {
    let output = Command::new("sudo")
        .arg("systemctl")
        .arg("restart")
        .arg("Chromia")
        .output()?;

    if output.status.success() {
        append_to_log(&format!("[Info] IDS started successfully."));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        append_to_log(&format!("[INTERNAL ERROR] Failed to start IDS: {}", error_message));
    }
    
    Ok(())
}


fn reinstall_ids() -> Result<(), io::Error> {
    // Define the temporary directory and the target binary path
    let temp_dir = "/tmp/tpm";
    let target_binary_path = "/bin/Chromia";

    fs::remove_dir_all(temp_dir)?;
    println!("Marker reinstall.");
    // Clone the repository into the temporary directory
    let clone_status = Command::new("git")
        .args(&[
            "clone",
            "--branch",
            "mainpluservice", // Replace with the actual branch name
            "https://github.com/erikkvietelaitis/COS40005-Intrusion-Detection-System", // Replace with the actual repository URL
            temp_dir,
        ])
        .status()?;

    if !clone_status.success() {
        eprintln!("Failed to clone the repository.");
        return Err(io::Error::new(io::ErrorKind::Other, "Clone failed"));
    }

    // Move the compiled binary from the temporary directory to the target path
    let binary_source = format!("{}/Chromia", temp_dir); // Adjust if necessary
    fs::rename(&binary_source, target_binary_path)?;

    Ok(())
}
    

fn is_service_running(service_name: &str) -> Result<bool, io::Error> {
    // Execute the systemctl command to check the service status
    let output = Command::new("systemctl")
        .args(&["is-active", service_name])
        .output()?;

    if !Path::new("/bin/Chromia/Chromia").exists() {
        let _ = reinstall_ids(); 
    }

    // Check if the command was successful
    if output.status.success() {
        // Check the output to see if the service is active
        let status = String::from_utf8_lossy(&output.stdout);
        Ok(status.trim() == "active")
    } else {
        // If the service is not found or other errors occur
        Ok(false)
    }
}

fn genhash(key: &str) -> (bool, String) {
    let output = match Command::new("/bin/Chromia/Data/b3sum")
        .arg(key)
        .arg("--no-names")
        .output() {
        
        Ok(output) => output,
        Err(err) => {
            append_to_log(&format!("[INTERNAL ERROR] Failed to hash for key '{}': {}", key, err));
            return (false, String::new());
        }
    };
    // Convert output to string
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();
    
    //println!("{}", stdout_str);

    if !stderr_str.is_empty() {
        append_to_log(&format!("[Info] stderr for key '{}': {}", key, stderr_str));
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
