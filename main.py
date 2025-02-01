import subprocess
import time
import threading
from snifox import Snifox

#----------------------------------------- PART I ----------------------------------------------#
# Setup

pcap_file = "6.pcap"
interface = "enp0s1"  

sniffer = Snifox(mode="raw", interface=interface)
sniffer_thread = threading.Thread(target=sniffer.start_sniffer)
sniffer_thread.start()

# Start Sniffing
snifox_process = subprocess.Popen(["sudo", "python3", snifox_script, "--mode", "raw", "--interface", interface])
time.sleep(2)

# Start tcpreplay
tcpreplay_process = subprocess.Popen(
    ["sudo", "tcpreplay", "-i", interface, "--mbps=150", pcap_file]
)
tcpreplay_process.wait()

# Stop Sniffing
time.sleep(5)# Setup
sniffer.stop()
sniffer_thread.join()

print("Replay completed, sniffer stopped.")

#----------------------------------------- PART II ----------------------------------------------#

print("Starting Catch The Flag")
# Run Snifox_Advanced for Catch the Flag
#snifox_advanced_process = subprocess.Popen(["python3", snifox_advanced_script])
#snifox_advanced_process.wait()

print("Catch the Flag completed.")
