#!/usr/bin/env python3

import sys
from netmiko import ConnectHandler

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]
vlan_id = sys.argv[5]
vlan_name = sys.argv[6]

print("===== DEBUG START =====")
print(f"Parameters received: host={host}, user={username}, port={port}, vlan_id={vlan_id}, vlan_name={vlan_name}")

device = {
    "device_type": "cisco_s300",
    "host": host,
    "username": username,
    "password": password,
    "port": int(port),
}

print("Device config object:")
print(device)

try:
    print("Attempting to connect to device...")
    net_connect = ConnectHandler(**device)
    print("Connected successfully!")

    print("Sending configuration commands:")
    commands = [
        "conf t",
        f"vlan {vlan_id}",
        f"name {vlan_name}",
        "exit",
        "exit",
        "write memory"
    ]
    print(commands)

    output = net_connect.send_config_set(commands)
    print("----- Command output -----")
    print(output)
    print("--------------------------")

    net_connect.disconnect()
    print("Disconnected from device.")
    print("===== DEBUG END SUCCESS =====")
except Exception as e:
    print("!!!!! EXCEPTION OCCURRED !!!!!")
    import traceback
    traceback.print_exc()
    print("Error:", str(e))
    print("===== DEBUG END FAILURE =====")
    sys.exit(1)
