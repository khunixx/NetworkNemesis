# Network Nemesis  

Network Nemesis is an advanced **network attack and exploitation framework** designed for penetration testers and cybersecurity professionals. It automates **password brute-forcing, ARP spoofing, Metasploit payload creation, and network scanning** while maintaining structured logging for analysis.  

This tool enables **offensive security assessments**, helping ethical hackers **test network defenses, identify vulnerabilities, and execute targeted attacks** in controlled environments.  

---

## Table of Contents  

1. [Overview](#overview)  
2. [Features](#features)  
3. [Prerequisites](#prerequisites)  
4. [Tested On](#tested-on)  
5. [Usage](#usage)  
6. [Script Workflow](#script-workflow)    

---

## Overview  

Network Nemesis automates the following network penetration testing tasks:  

- **Brute-force attacks** on SSH, FTP, Telnet, and other services.  
- **ARP Spoofing & Man-in-the-Middle (MITM) attacks** to intercept network traffic.  
- **Metasploit Payload Creation** for crafting backdoor shells.  
- **Network scanning and host discovery** using Nmap.  
- **Logging and forensic reporting** for post-exploitation analysis.  

### Use Cases:  

- **Penetration Testing** – Identify weak passwords, vulnerable services, and exploitable targets.  
- **Red Team Operations** – Simulate real-world network attacks in controlled environments.  
- **Security Auditing** – Test system resilience against brute-force and MITM attacks.  

---

## Features  

### 1. Automated Dependency Check  
- Ensures required tools (**Hydra, Dsniff, Nmap, Metasploit, tcpdump**) are installed.  

### 2. Brute-Force Attack Modules  
- Uses **Hydra** to brute-force SSH, FTP, Telnet, and more.  
- Supports **custom password lists** for targeted attacks.  

### 3. Network Reconnaissance & Scanning  
- Uses **Nmap** for host discovery and service enumeration.  
- Identifies **open ports, running services, and vulnerabilities**.  

### 4. ARP Spoofing & MITM Attacks  
- Uses **Dsniff** for intercepting and manipulating network traffic.  
- Can be used to sniff credentials from unencrypted protocols.  

### 5. Exploit & Payload Generation  
- Generates **Metasploit payloads** for remote exploitation.  
- Can create **reverse shells and bind shells** for penetration testing.  

### 6. Logging & Reporting  
- Saves attack logs for forensic analysis.  
- Generates a structured output of brute-force results and intercepted data.  

---

## Prerequisites  

This script checks for and installs the following tools if they are not already present:  

- **Hydra** – Password brute-forcing tool.  
- **Dsniff** – ARP spoofing & MITM attack tool.  
- **Nmap** – Network scanner for host and service discovery.  
- **Metasploit Framework** – Exploitation framework for payload creation.  
- **tcpdump** – Packet capture tool for network analysis.  

> **Note**: The script relies on `apt-get` for package installation and is primarily tested on **Debian/Ubuntu-based** systems.  

---

## Tested On  

- **Kali Linux** (Debian-based)  
- **Ubuntu 20.04+**  

---

## Usage  

### 1. Clone the Repository  

```bash
git clone https://github.com/khunixx/NetworkNemesis.git
cd NetworkNemesis
```

### 2. Make the Script Executable  

```bash
chmod +x NetworkNemesis.sh
```

### 3. Run the Script  

```bash
sudo ./NetworkNemesis.sh
```

### 4. Follow the Prompts  

- Choose your attack mode (**Brute-force, MITM, Exploitation, or Recon**).  
- Provide the **target IP address** or **network range** if required.  
- The script will execute the attack and save logs for further analysis.  

---

## Script Workflow  

### 1. CHECK  
- Ensures root access and verifies dependencies.  

### 2. NETWORK SCANNING  
- Uses **Nmap** to detect live hosts and open ports.  

### 3. BRUTE-FORCE ATTACKS  
- Uses **Hydra** to attempt SSH, FTP, Telnet password attacks.  

### 4. ARP SPOOFING & MITM  
- Uses **Dsniff** to intercept network traffic and capture credentials.  

### 5. EXPLOITATION & PAYLOADS  
- Generates **Metasploit payloads** for remote access.  
- Executes **exploits against vulnerable services** if found.  

### 6. LOGGING & REPORTING  
- Stores all results in `/var/log`.  

---

