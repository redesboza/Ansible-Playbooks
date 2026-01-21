#!/usr/bin/env python3

import sys
from netmiko import ConnectHandler
import os

# Argumentos desde el playbook
vlan_id = sys.argv[1]
vlan_name = sys.argv[2]

# AWX pasa automáticamente estas variables de entorno si usas credenciales SSH
host_ip = os.environ.get("ANSIBLE_HOST")
username = os.environ.get("ANSIBLE_NET_USERNAME") or os.environ.get("ANSIBLE_USER")
password = os.environ.get("ANSIBLE_NET_PASSWORD") or os.environ.get("ANSIBLE_PASSWORD")

device = {
    "device_type": "cisco_s300",  # Para SG350
    "host": host_ip,
    "username": username,
    "password": password,
    "port": 11110,  # Puerto SSH personalizado
}

commands = [
    f"vlan {vlan_id}",
    f"name {vlan_name}",
    "exit",
    "do wr mem"
]

try:
    connection = ConnectHandler(**device)
    output = connection.send_config_set(commands)
    print(output)
    connection.disconnect()
except Exception as e:
    print(f"ERROR: {str(e)}")
    sys.exit(1)

