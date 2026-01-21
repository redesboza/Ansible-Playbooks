import sys
from netmiko import ConnectHandler

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]
vlan_id = sys.argv[5]
vlan_name = sys.argv[6]

device = {
    'device_type': 'cisco_s300',
    'host': host,
    'username': username,
    'password': password,
    'port': port,
}

print("🔧 Conectando al switch para configurar VLAN...")

try:
    net_connect = ConnectHandler(**device)
    net_connect.enable()

    commands = [
        "vlan database",
        f"vlan {vlan_id}",
        "exit",
        f"interface vlan {vlan_id}",
        f"name {vlan_name}",
        "exit"
    ]

    output = net_connect.send_config_set(commands)
    print("✅ Configuración aplicada:")
    print(output)
    net_connect.disconnect()

except Exception as e:
    print(f"❌ Error durante la configuración: {e}")
