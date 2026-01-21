#!/usr/bin/env python3

import sys
import os
from netmiko import ConnectHandler

# Parámetros pasados por AWX
host = os.environ.get("ANSIBLE_HOST")
username = os.environ.get("ANSIBLE_NET_USERNAME")
password = os.environ.get("ANSIBLE_NET_PASSWORD")
port = os.environ.get("ANSIBLE_NET_PORT", 11110)  # Default a 22 si no se especifica

# Argumentos desde el Playbook
if len(sys.argv) != 3:
    print("Uso: crear_vlan.py <vlan_id> <nombre_vlan>")
    sys.exit(1)

vlan_id = sys.argv[1]
nombre_vlan = sys.argv[2]

device = {
    "device_type": "cisco_s300",
    "host": host,
    "username": username,
    "password": password,
    "port": int(port),
}

try:
    net_connect = ConnectHandler(**device)
    commands = [
        "conf t",
        f"interface vlan {vlan_id}",
        f"name {nombre_vlan}",
        "exit",
        "do wr",
        "y",
    ]
    output = net_connect.send_config_set(commands)
    print(output)
    net_connect.disconnect()

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
