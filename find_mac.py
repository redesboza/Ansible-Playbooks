#!/usr/bin/env python3
import pexpect
import re
import sys

'''
Cisco SG - Buscar MAC en tabla y ver puerto

Uso:
  python3 find_mac.py <host> <ssh_user> <ssh_password> <port> <mac>

Ejemplos de mac:
  00:11:22:33:44:55
  0011.2233.4455
'''

if len(sys.argv) != 6:
    print("❌ Uso: python3 find_mac.py <host> <ssh_user> <ssh_password> <port> <mac>")
    sys.exit(1)

host, ssh_user, ssh_password, port, mac_in = sys.argv[1:6]

# Normaliza MAC (acepta xx_xx_xx_xx_xx_xx o con -) => 00:11:22:33:44:55
mac = mac_in.replace("_", ":").replace("-", ":").lower()

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...")
ssh_cmd = (
    f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-p {port} {ssh_user}@{host}"
)
child = pexpect.spawn(ssh_cmd, timeout=35, encoding="utf-8")

def expect_prompt(timeout=35):
    child.timeout = timeout
    i = child.expect([r"#\s*$", r">\s*$"])
    return "#" if i == 0 else ">"

try:
    # Login robusto
    while True:
        i = child.expect([
            r"Are you sure you want to continue connecting \(yes/no\)\?",
            r"login as:",
            r"User Name:",
            r"Username:",
            r"Password:",
            r"#\s*$",
            r">\s*$",
            r"Press any key to continue",
            r"--More--",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ])
        if i == 0:
            child.sendline("yes")
        elif i in (1, 2, 3):
            child.sendline(ssh_user)
        elif i == 4:
            child.sendline(ssh_password)
        elif i in (5, 6):
            break
        elif i == 7:
            child.sendline("")
        elif i == 8:
            child.send(" ")
        else:
            print("❌ No se pudo establecer sesión SSH (timeout/EOF).")
            sys.exit(1)

    # Refrescar prompt + desactivar paginación
    child.sendline("")
    prompt = expect_prompt()
    child.sendline("terminal length 0")
    child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF], timeout=10)

    cmd = f"show mac address-table address {mac}"
    print(f"🔎 Ejecutando: {cmd}")
    child.sendline(cmd)

    # Captura salida hasta el prompt
    child.expect([r"#\s*$", r">\s*$"], timeout=35)
    output = child.before

    print("----- OUTPUT -----")
    print(output.strip())
    print("------------------")

    # Intento de extracción de interfaz/puerto (best-effort)
    # En SG suele aparecer algo como: ...  Dynamic  Gi1/0/5  o  g1
    m = re.search(r"(Gi\\S+|gi\\S+|Fa\\S+|fa\\S+|Te\\S+|te\\S+|Po\\S+|po\\S+|g\\d+|G\\d+)", output)
    if m:
        print(f"✅ Puerto/Interfaz detectada: {m.group(1)}")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error buscando MAC: {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)
