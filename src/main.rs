use pcap::{Capture, Device};
use std::time::SystemTime;
use sqlite::Connection;
use std::process::Command;

fn main() {
    // Find available network devices
    let devices = Device::list().expect("Failed to get devices");
    let device = devices.into_iter().find(|d| d.name == "en0")  // Change to your active interface
        .expect("No en0 device found");

    println!("Listening on device: {}", device.name);

    // Open the capture device
    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .promisc(true)  // Enable promiscuous mode to capture all packets
        .snaplen(5000)  // Limit packet size
        .open()
        .expect("Failed to start capture");

    // Open SQLite database for logging
    let conn = Connection::open("packets.db").expect("Failed to open database");

    // Create table if it doesn't exist
    conn.execute("
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            length INTEGER
        )
    ").expect("Failed to create table");

    // Capture packets
    while let Ok(packet) = cap.next_packet() {
        let timestamp = SystemTime::now();
        let length = packet.header.len;
        let data = packet.data;

        // Parse source and destination IPs (basic parsing for IPv4)
        let (src_ip, dest_ip) = if data.len() >= 34 {
            let src = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
            let dest = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
            (src, dest)
        } else {
            ("Unknown".to_string(), "Unknown".to_string())
        };

        // Print packet info
        println!("Packet: {} -> {} | {} bytes", src_ip, dest_ip, length);

        // Insert packet into SQLite database
        conn.execute(format!(
            "INSERT INTO packets (timestamp, src_ip, dest_ip, length) VALUES ('{:?}', '{}', '{}', {})",
            timestamp, src_ip, dest_ip, length
        )).expect("Failed to insert packet");
    }

    // Run firewall tests
    println!("NetSentinelX Firewall Test:");
    
    block_ip("8.8.8.8"); // Example: Block Google DNS
    list_rules();  // Print active rules
    
    println!("Press Enter to clear firewall...");
    let _ = std::io::stdin().read_line(&mut String::new());
    
    clear_firewall();
    list_rules();  // Confirm it's empty
}

// Function to block an IP
fn block_ip(ip: &str) {
    let rule = format!("block drop out quick on en0 from any to {}", ip);
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("echo \"{}\" | sudo tee -a /etc/pf.anchors/netsentinelx && sudo pfctl -f /etc/pf.conf", rule))
        .output()
        .expect("Failed to execute firewall rule");

    println!("Blocked IP: {}", ip);
}

// Function to clear all firewall rules
fn clear_firewall() {
    let _ = Command::new("sh")
        .arg("-c")
        .arg("sudo rm /etc/pf.anchors/netsentinelx && sudo touch /etc/pf.anchors/netsentinelx && sudo pfctl -f /etc/pf.conf")
        .output()
        .expect("Failed to clear firewall rules");

    println!("All firewall rules cleared.");
}

// Function to list active firewall rules
fn list_rules() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("sudo pfctl -sr")
        .output()
        .expect("Failed to list firewall rules");

    println!("{}", String::from_utf8_lossy(&output.stdout));
}