use std::time::Duration;
use std::thread;
use std::fs::OpenOptions;
use std::process::Command;
use std::io::Write;
use std::str;
use std::io;



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


    loop {
        //rate limiter
        thread::sleep(Duration::from_secs(1));
        if i >= num_iterations {
            break;
        }
        i += 1;

        //check IDS binary is correct
        let bintpm_path = "/bin/Chromia/Chromia";
        let (bbo, exec_hash) = genhash(&bintpm_path);
        if bbo {
            append_to_log(&format!("[DEBUG] IDS Hash: '{}'", exec_hash.trim()));
            if exec_hash.trim() == "4aadf5d3b0865451747b4832647852acc80c0985da3979499296a5ce439bd711".to_string() {
                append_to_log(&format!("[Info] No tamper found for IDS."));
            } else {
                append_to_log(&format!("[Serious] Hash for IDS not matching."));
                if let Err(e) = reinstall_ctpb_tpm() {
                    append_to_log(&format!("[INTERNAL ERROR]: {}", e));
                } else {
                    append_to_log(&format!("[Info] IDS Installation completed successfully!"));
                }
            }
        } else {
            append_to_log(&format!("[Warning] Unable to hash IDS binary."));
        }
        

        //check IDS is running
        let service_name = "Chromia.service";
        match is_service_running(service_name) {
            Ok(true) => append_to_log(&format!("[Info] '{}' is running.", service_name)),
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


fn reinstall_ctpb_tpm() -> Result<(), io::Error> {
    // Clone the repository
    Command::new("git")
        .args(&["clone", "https://github.com/brokenpip/ctpb_ids.git", "/tmp/Chromia/TPM"])
        .status()?;

    // Change directory and build the project
    Command::new("cargo")
        .current_dir("/tmp/Chromia/TPM/ctpb_ids")
        .args(&["build", "--release"])
        .status()?;

    // Move the built binary to /bin/Chromia
    Command::new("sudo")
        .args(&["mv", "/tmp/Chromia/TPM/ctpb_ids/target/release/ctpb_tpm", "/bin/Chromia"])
        .status()?;

    // Clean up
    Command::new("sudo")
        .args(&["rm", "-rf", "/tmp/Chromia"])
        .status()?;

    Ok(())
}

fn is_service_running(service_name: &str) -> Result<bool, io::Error> {
    // Execute the systemctl command to check the service status
    let output = Command::new("systemctl")
        .args(&["is-active", service_name])
        .output()?;

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
