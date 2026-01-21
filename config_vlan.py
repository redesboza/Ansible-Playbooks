#!/usr/bin/env python3

import pexpect
import sys

if len(sys.argv) != 7:
    print("❌ Uso incorrecto:")
    print("python3 config_vlan.py <host> <user> <password> <port> <vlan_id> <vlan_name>")
    sys.exit(1)

host      = sys.argv[1]
user      = sys.argv[2]
password  = sys.argv[3]
port      = sys.argv[4]
vlan_id   = sys.argv[5]
vlan_name = sys.argv[6]

print(f"🔐 Conectando a {host}:{port} como {user}...")

ssh_cmd = f"ssh -o StrictHostKeyChecking=no -p {port} {user}@{host}"
child = pexpect.spawn(ssh_cmd, timeout=20)

try:
    while True:
        i = child.expect([
            "login as:",
            "User Name:",
            "Password:",
            "#",
            ">",              # algunos SG350 dan prompt >
            pexpect.TIMEOUT,
            pexpect.EOF
        ])

        if i == 0 or i == 1:
            child.sendline(user)
        elif i == 2:
            child.sendline(password)
        elif i == 3 or i == 4:
            print("✅ Conectado. Iniciando configuración de VLAN...")
            break
        else:
            print("❌ No se pudo establecer sesión SSH.")
            sys.exit(1)

    # Enviar comandos de configuración
    child.sendline("configure terminal")
    child.expect(["#", ">"])

    child.sendline(f"vlan {vlan_id}")
    child.expect(["#", ">"])

    child.sendline(f"name {vlan_name}")
    child.expect(["#", ">"])

    child.sendline("end")
    child.expect(["#", ">"])

    print(f"✅ VLAN {vlan_id} ({vlan_name}) configurada con éxito.")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error durante configuración: {e}")
    sys.exit(1)
