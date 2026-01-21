#!/usr/bin/env python3

import sys
from netmiko import ConnectHandler
import os

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]
vlan_id = sys.argv[5]
nombre_vlan = sys.argv[6]

device = {
    'device_type': 'cisco_s300',
    'host': host,
    'username': username,
    'password': password,
    'port': port,
}
print("DEBUG DEVICE:", device)

net_connect = ConnectHandler(**device)

commands = [
    f"vlan database",
    f"vlan {vlan_id}",
    f"exit",
    f"interface vlan {vlan_id}",
    f"name {nombre_vlan}",
    f"exit"
]

output = net_connect.send_config_set(commands)
print(output)
net_connect.disconnect()
