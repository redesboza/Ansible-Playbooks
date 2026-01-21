from netmiko import ConnectHandler
import sys

def main():
    # sys.argv = [script, host, user, pass, port, vlan_id, vlan_name]
    if len(sys.argv) != 7:
        print("❌ Uso incorrecto:")
        print("python3 config_vlan.py <host> <user> <pass> <port> <vlan_id> <vlan_name>")
        sys.exit(1)

    _, host, user, password, port, vlan_id, vlan_name = sys.argv

    device = {
        "device_type": "cisco_s300",
        "host": host,
        "username": user,
        "password": password,
        "port": int(port),
        "fast_cli": False
    }

    print(f"🔐 Conectando a {host}:{port}...")

    try:
        net_connect = ConnectHandler(**device)
        print("✅ Autenticación OK")

        # Entrar a modo configuración y crear VLAN
        commands = [
            f"vlan {vlan_id}",
            f"name {vlan_name}",
            "exit"
        ]

        print(f"⚙️ Creando VLAN {vlan_id} ({vlan_name})")
        output = net_connect.send_config_set(commands)
        print("📤 Salida del switch:")
        print(output)

        net_connect.save_config()
        print("💾 Configuración guardada")

        net_connect.disconnect()
        print("🔒 Sesión cerrada correctamente")

    except Exception as e:
        print(f"❌ Error durante la configuración: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
