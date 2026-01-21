#!/usr/bin/env python3

import sys
from netmiko import ConnectHandler

# Leer argumentos del playbook
host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]

device = {
    "device_type": "cisco_s300",
    "host": host,
    "username": username,
    "password": password,
    "port": int(port),
    "timeout": 10
}

print(f"Conectando a {host}:{port} con usuario {username}...")

try:
    net_connect = ConnectHandler(**device)
    prompt = net_connect.find_prompt()
    print(f"✅ Conectado correctamente. Prompt: {prompt}")
    net_connect.disconnect()
    print("🔌 Desconectado exitosamente.")
except Exception as e:
    print(f"❌ Error de conexión: {e}")
    sys.exit(1)
