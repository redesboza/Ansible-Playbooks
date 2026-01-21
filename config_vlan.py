#!/usr/bin/env python3

import sys
from netmiko import ConnectHandler

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]
vlan_id = sys.argv[5]
vlan_name = sys.argv[6]

device = {
    "device_type": "cisco_s300",
    "host": host,
    "username": username,
    "password": password,
    "port": int(port),
}

print(f"Conectando a {host}:{port}...")

try:
    net_connect = ConnectHandler(**device)

    # Entrar a modo global
    net_connect.enable()

    commands = [
        "conf t",
        f"vlan {vlan_id}",
        f"name {vlan_name}",
        "exit",
        "exit",
        "write memory"
    ]

    output = net_connect.send_config_set(commands)
    print("Salida de configuración:\n", output)

    net_connect.disconnect()
    print("Conexión cerrada.")

except Exception as e:
    print("❌ Error:", e)
    sys.exit(1)
