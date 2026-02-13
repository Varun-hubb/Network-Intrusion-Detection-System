# Network-Intrusion-Detection-System
## Objective

The objective of this project is to design, implement, and evaluate a Network Intrusion Detection System (NIDS) using Snort in a controlled virtual environment. The system is developed to monitor real-time network traffic, detect common cyber attacks through custom rules, and generate timely security alerts. This project aims to enhance network visibility, improve incident response capability, and demonstrate practical skills in intrusion detection and network security.
## Architecture

The project is implemented in a virtualized lab environment consisting of two main systems: an attacker machine and a target machine. Kali Linux is used to simulate various network attacks, while Ubuntu Server hosts the Snort-based Intrusion Detection System. Both virtual machines are connected using a bridged network configuration, allowing them to communicate as if they were on the same physical network. Snort continuously monitors network traffic on the Ubuntu server, analyzes packets using custom detection rules, and generates real-time alerts when suspicious activity is detected.

### System Architecture Diagram
![System Architecture](https://github.com/Varun-hubb/Network-Intrusion-Detection-System/blob/main/screenshots/NIDS.drawio%20(1).png)

## Technologies Used

| Category           | Tools / Technologies                 |
|--------------------|--------------------------------------|
| Operating Systems  | Ubuntu Server, Kali Linux            |
| Intrusion Detection| Snort                                |
| Virtualization     | VMware / VirtualBox                 |
| Network Tools      | Nmap, Hydra, Curl                   |
| Network Services   | OpenSSH, vsftpd, Apache              |
| Scripting          | Bash                                 |

## Installation and Procedure

### Step 1: Environment Setup

Create a virtual lab environment using VMware or VirtualBox.

Set up two virtual machines:

- Ubuntu Server (Target system with Snort IDS)
- Kali Linux (Attacker system)

Configure both virtual machines in **Bridged Network Mode** so that they can communicate on the same local network.

Ensure that both machines can ping each other before proceeding.

### Step 2: Install Required Tools

After setting up both virtual machines, install the necessary tools.

#### On Ubuntu Server (Target + IDS)

Update the system and install Snort along with required services:

```bash
sudo apt update
sudo apt install -y snort openssh-server vsftpd apache2 tcpdump
```
#### On Kali Linux (Attacker Machine)

Update the system and install attack simulation tools:

```bash
sudo apt update
sudo apt install -y nmap hydra curl
```
Verify tool availability:
```bash
nmap --version
hydra -h
```

### Step 3: Configure Snort Detection Rules

Custom detection rules are added to enable identification of different attack patterns.

Open the local rules file:

```bash
sudo nano /etc/snort/rules/local.rules
```

Add custom rules for detecting:

- ICMP echo requests

- Nmap reconnaissance scans

- SSH brute-force attempts

- FTP brute-force attempts

- Malware C2 communication

Example ICMP detection rule:
```bash
alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1000000; rev:1;)
```
(local.rules pic here)

### Step 4: Run Snort in IDS Mode

Start Snort in Intrusion Detection mode to monitor live network traffic.

Identify your active network interface:

```bash
ip a
```
Start Snort
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i enp2s1
```
Explanation of parameters:

-A console → Displays alerts directly in the terminal

-q → Runs Snort in quiet mode

-c → Specifies the configuration file

-i → Defines the network interface to monitor

Snort will now analyze incoming traffic and generate alerts based on the configured rules

### Step 5: Simulate Attacks from Kali Linux

Various attacks are simulated from the Kali Linux machine to test the effectiveness of the IDS.

---

#### 1. ICMP Ping Test

Send ICMP echo requests to the target system:

```bash
ping -c 5 <target-ip>
```
Expected Result: Snort generates alerts for ICMP traffic.

![(ICMP Result here)](https://github.com/Varun-hubb/Network-Intrusion-Detection-System/blob/main/screenshots/icmp_ping_test.png)

#### 2. Nmap Reconnaissance Scan

Perform TCP SYN scan on the target:
```bash
nmap -sS <target-ip>
```
Expected Result: Snort detects reconnaissance activity.
![(syn scan result here)](https://github.com/Varun-hubb/Network-Intrusion-Detection-System/blob/main/screenshots/Nmap_syn_scan.png)

#### 3. SSH Brute-Force Attack

Create a password list:
```bash
echo -e "password\nadmin\nroot\n123456\nqwerty\nletmein" > pass.txt
```
Launch brute-force attack:
```bash
hydra -l testuser -P pass.txt ssh://<target-ip>
```
Expected Result: Snort triggers SSH brute-force alerts.
![(ssh result here)](https://github.com/Varun-hubb/Network-Intrusion-Detection-System/blob/main/screenshots/ssh_bruteforce.png)

#### 4. FTP Brute-Force Attack

Launch FTP brute-force attack:
```bash
hydra -l testuser -P pass.txt ftp://<target-ip>
```
Expected Result: Snort detects repeated login attempts.
![(ftp result here)](https://github.com/Varun-hubb/Network-Intrusion-Detection-System/blob/main/screenshots/ftp_bruteforce.png)

#### 5. Malware C2 Beacon Simulation

Simulate periodic beaconing traffic:
```bash
while true; do curl -H "Host: malicious-c2-server.com" http://<target-ip>/ping; sleep 10; done
```
Expected Result: Snort detects malicious domain and beacon URI.
![(result here)](https://github.com/Varun-hubb/Network-Intrusion-Detection-System/blob/main/screenshots/malware_c2.png)

## Future Scope

The current implementation of the Network Intrusion Detection System provides effective detection of known attack patterns. However, several enhancements can be introduced to improve its scalability, intelligence, and automation.

Future improvements may include:

- Integration with SIEM platforms such as ELK Stack or Splunk for centralized monitoring
- Implementation of machine learning models for anomaly-based intrusion detection
- Development of automated response mechanisms using IPS and SOAR tools
- Cloud-based deployment for monitoring distributed environments
- Real-time dashboard for visualization of security events
- Advanced threat intelligence integration for dynamic rule updates

These enhancements will increase the system’s ability to detect sophisticated threats and improve overall network security posture.
