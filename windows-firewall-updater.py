# Author: Sneaky Celery
# This script utilizes Open Source Intelligence(OSINT) to block known malicious IPs from 
# communicating with your system and vice-versa. This one in particular is protecting against
# botnets.

import requests, csv, subprocess, ipaddress

# Source=Abuse CH
response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").text

# Filter out comments
mycsv = csv.reader(filter(lambda x: not x.startswith("#"), response.splitlines()))

# Verify that the expected IP addresses are found in the csv file before continuing.
ip_list = []
for row in mycsv:
    if len(row) > 1 and row[1].count(".") == 3:
        try:
            ip = str(ipaddress.ip_address(row[1]))
            if ip != "dst_ip":
                ip_list.append(ip)
        except ValueError:
            continue
if not ip_list:
    print("No valid IP address found. Exiting script.")
    exit(1)

# Delete existing firewall rules
rule = "netsh advfirewall firewall delete rule name='BadIP'"
subprocess.run(["Powershell", "-Command", rule])

# Create new firewall rules for inbound and outbound traffic
for ip in ip_list:
    print("Added Rule to block ",ip)
    rule = "netsh advfirewall firewall add rule name='BadIP' Dir=Out Action=Block RemoteIP="+ip
    subprocess.run(["Powershell", "-Command", rule])
    rule = "netsh advfirewall firewall add rule name='BadIP' Dir=In Action=Block RemoteIP="+ip
    subprocess.run(["Powershell", "-Command", rule])
