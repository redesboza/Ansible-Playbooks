#!/usr/bin/env python3

import pexpect
import sys

host = sys.argv[1]
user = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]
vlan_id = sys.argv[5]
vlan_name = sys.argv[6]

print(f"🔧 Configuración VLAN: ID={vlan_id}, Nombre={vlan_name}")
ssh_cmd = f"ssh -o StrictHostKeyChecking=no -p {port} {user}@{host}"
child = pexpect.spawn(ssh_cmd, timeout=30)

try:
    while True:
        i = child.expect([
            "login as:",
            "User Name:",
            "Password:",
            "#",
            "Do you want to change it now (Y/N)",
            pexpect.TIMEOUT,
            pexpect.EOF
        ])

        if i == 0:
            child.sendline(user)
        elif i == 1:
            child.sendline(user)
        elif i == 2:
            child.sendline(password)
        elif i == 3:
            print("✅ Conexión SSH establecida, configurando VLAN...")
            break
        elif i == 4:
            child.sendline("N")
        else:
            print("❌ Error: No se pudo establecer la conexión.")
            sys.exit(1)

    # Enviar comandos para configurar la VLAN
    child.sendline("configure terminal")
    child.expect("#")

    child.sendline(f"vlan {vlan_id}")
    child.expect("#")

    child.sendline(f"name {vlan_name}")
    child.expect("#")

    child.sendline("end")
    child.expect("#")

    print(f"✅ VLAN {vlan_id} - '{vlan_name}' configurada correctamente.")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error durante configuración: {e}")
    sys.exit(1)

