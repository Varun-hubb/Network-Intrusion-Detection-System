# Network-Intrusion-Detection-System
## Objective

The objective of this project is to design, implement, and evaluate a Network Intrusion Detection System (NIDS) using Snort in a controlled virtual environment. The system is developed to monitor real-time network traffic, detect common cyber attacks through custom rules, and generate timely security alerts. This project aims to enhance network visibility, improve incident response capability, and demonstrate practical skills in intrusion detection and network security.
## Architecture

The project is implemented in a virtualized lab environment consisting of two main systems: an attacker machine and a target machine. Kali Linux is used to simulate various network attacks, while Ubuntu Server hosts the Snort-based Intrusion Detection System. Both virtual machines are connected using a bridged network configuration, allowing them to communicate as if they were on the same physical network. Snort continuously monitors network traffic on the Ubuntu server, analyzes packets using custom detection rules, and generates real-time alerts when suspicious activity is detected.

### System Architecture Diagram

