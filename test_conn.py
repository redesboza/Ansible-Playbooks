from netmiko import ConnectHandler
import sys

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]

device = {
    'device_type': 'cisco_s300',
    'host': host,
    'username': username,
    'password': password,
    'port': port,
}

print("🔍 DEBUG DEVICE CONFIG:")
print(device)

try:
    print(f"Intentando conexión con {host}...")
    net_connect = ConnectHandler(**device)
    print("✅ Conexión exitosa a", host)
    net_connect.disconnect()
except Exception as e:
    print("❌ Error al conectar a", host)
    print(e)
    sys.exit(1)
