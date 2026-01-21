from netmiko import ConnectHandler
import sys

def main():
    if len(sys.argv) != 8:
        print("❌ Uso incorrecto: python3 config_vlan.py <host> <user> <pass> <port> <vlan_id> <vlan_name>")
        sys.exit(1)

    _, host, user, password, port, vlan_id, vlan_name = sys.argv

    device = {
        "device_type": "cisco_s300",
        "host": host,
        "username": user,
        "password": password,
        "port": port
    }

    print(f"🔐 Conectando a {host}:{port}...")

    try:
        net_connect = ConnectHandler(**device)
        print("✅ Conexión exitosa.")

        # Comandos para crear la VLAN
        commands = [
            "vlan database",
            f"vlan {vlan_id} name {vlan_name}",
            "exit"
        ]
        print(f"⚙️ Configurando VLAN {vlan_id} con nombre '{vlan_name}'...")
        output = net_connect.send_config_set(commands)
        print("📤 Resultado:")
        print(output)

        net_connect.disconnect()
        print("🔒 Sesión cerrada correctamente.")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
