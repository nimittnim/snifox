import subprocess
#----------------------------------------- PART II ----------------------------------------------#
snifox_advanced_script = 'snifox_advanced.py'
print("Starting Catch The Flag")
# Run Snifox_Advanced for Catch the Flag
snifox_advanced_process = subprocess.Popen(["python3", snifox_advanced_script])
snifox_advanced_process.wait()

print("Catch the Flag completed.")
