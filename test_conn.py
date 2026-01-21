#!/usr/bin/env python3

import pexpect
import sys

host = sys.argv[1]
user = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]

print(f"🔍 DEBUG DEVICE CONFIG:")
print({
    "host": host,
    "username": user,
    "password": password,
    "port": port
})
print(f"Intentando conexión con {host}...")

ssh_cmd = f"ssh -o StrictHostKeyChecking=no -p {port} {user}@{host}"
child = pexpect.spawn(ssh_cmd, timeout=20)

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
            print("✅ Conexión SSH exitosa")
            child.sendline("exit")
            break
        elif i == 4:
            child.sendline("N")  # Si aparece el cambio de contraseña
        else:
            print("❌ Error: No se pudo establecer la conexión.")
            sys.exit(1)

except Exception as e:
    print(f"❌ Error de conexión: {e}")
    sys.exit(1)

