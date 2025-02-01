import subprocess
import time
import threading
from snifox import Snifox

#----------------------------------------- PART I ----------------------------------------------#
# Setup

pcap_file = "6.pcap"
interface = "enp0s1"  



# Start Sniffing
sniffer = Snifox(mode="raw", interface=interface)
sniffer_thread = threading.Thread(target=sniffer.start_sniffer)
sniffer_thread.start()

time.sleep(2)
print('Replay started')
# Start tcpreplay
tcpreplay_process = subprocess.Popen(
    ["sudo", "tcpreplay", "-i", interface, "--mbps=50", pcap_file]
)
print('-'*50)
print('Replay stats')
tcpreplay_process.wait()
print('-'*50)
# Stop Sniffing
time.sleep(5)# Setup
sniffer.stop()
sniffer_thread.join()



