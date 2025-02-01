# **Snifox**

## **Description**  
`snifox.py` is a **Network Packet Analyzer** implemented using Python's **raw sockets** for Linux systems. It was built as part of the **CS330 Computer Networks** assignment. The tool captures and analyzes live network packets.  

Additionally, `snifox.py` has another mode that uses **Scapy** for packet capture and analysis.  
`snifox_advanced.py` processes `6.pcap` (provided in the assignment) to extract the required information.

---

## **Instructions to Reproduce Results for Assignment**

### **Setup**  
Ensure your system has the required dependencies installed: matplotlib, scapy and tcpreplay.

#### **1. Install Required Packages**  
Run the following command in your terminal:
```sh
sudo apt update
sudo apt install tcpreplay python3-matplotlib python3-scapy
```

#### **2. Clone the Repository**  
```sh
git clone https://github.com/nimittnim/snifox/
cd snifox
```

---

### **Part I - Live Packet Capture & Replay**  
#### **Steps:**  
1. Place the `6.pcap` file in the main directory of the cloned repository.
2. Run the following command to start packet replay and capture:
   ```sh
   sudo python3 run_part1.py
   ```
3. The terminal will display the required results.

---

### **Part II - Analyzing the Given PCAP**  
#### **Steps:**  
1. Run the following command:
   ```sh
   sudo python3 run_part2.py
   ```
2. This will process the `6.pcap` file and display the extracted information.

---

## **Additional Notes**  
- `snifox.py` requires **root (sudo) privileges** for raw packet capture.
- It is **Linux-only** as it relies on `socket.AF_PACKET`.

  
