import subprocess
import time

#----------------------------------------- PART I ----------------------------------------------#
# Setup
snifox_script = "snifox.py"  
snifox_advanced_script = "snifox_advanced.py" 
pcap_file = "6.pcap"
interface = "enp0s1"  

# Start Sniffing
snifox_process = subprocess.Popen(["sudo", "python3", snifox_script, "--mode", "scapy", "--interface", interface])
time.sleep(2)

# Start tcpreplay
tcpreplay_process = subprocess.Popen(["sudo", "tcpreplay", "-i", interface, pcap_file])
tcpreplay_process.wait()

# Stop Sniffing
snifox_process.terminate()
snifox_process.wait()

print("Replay completed, sniffer stopped.")

#----------------------------------------- PART II ----------------------------------------------#

# Run Snifox_Advanced for Catch the Flag
snifox_advanced_process = subprocess.Popen(["python3", snifox_advanced_script])
snifox_advanced_process.wait()

print("Catch the Flag completed.")
