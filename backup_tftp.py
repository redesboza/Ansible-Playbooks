#!/usr/bin/env python3
import pexpect
import sys
from datetime import datetime

'''
Cisco SG (SG300/SG350/CBS) - Backup running-config a TFTP con copy

Comando objetivo (ejemplo):
  copy running-config tftp://192.168.57.11/HOST_IP_20260122-1619_running.cfg

El script:
- Mantiene autenticación robusta (login as/User Name/Username/Password, hostkey yes/no)
- Fuerza TTY con ssh -tt
- Refresca prompt y desactiva paginación (terminal length 0) cuando aplica
- Ejecuta el copy y responde prompts típicos:
  - confirm / (Y/N) / Overwrite
  - Destination filename / remote host (si el equipo lo pide)

Uso:
  python3 backup_tftp.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>
Donde backup_basename puede ser: "MANTA_CORE_172.16.45.33" (sin extensión)
'''

if len(sys.argv) != 7:
    print("❌ Uso incorrecto:")
    print("python3 backup_tftp.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>")
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = sys.argv[4]
tftp_server  = sys.argv[5]
basename     = sys.argv[6]

ts = datetime.now().strftime("%Y%m%d-%H%M%S")
filename = f"{basename}_{ts}_running.cfg"

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...")
print(f"📦 Backup a TFTP: {tftp_server}  archivo: {filename}")

ssh_cmd = (
    f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-p {port} {ssh_user}@{host}"
)
child = pexpect.spawn(ssh_cmd, timeout=45, encoding="utf-8")

def expect_prompt(timeout=45):
    '''Espera prompt privilegiado '#' o no-privilegiado '>' y devuelve '#' o '>' '''
    child.timeout = timeout
    i = child.expect([r"#\s*$", r">\s*$"])
    return "#" if i == 0 else ">"

try:
    # --- Autenticación ---
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
            print(child.before[-400:])
            sys.exit(1)

    # Refrescar prompt (por banners/syslog)
    child.sendline("")
    prompt = expect_prompt(timeout=45)

    # Si entra a modo '>' intenta enable
    if prompt == ">":
        child.sendline("enable")
        k = child.expect([r"Password:", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        if k == 0:
            child.sendline(ssh_password)
            child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        child.sendline("")
        prompt = expect_prompt(timeout=45)

    if prompt != "#":
        print("⚠️ No quedé en modo privilegiado '#'. Puede fallar el copy si no tienes permisos.")

    # Desactivar paginación (si el comando no aplica, no pasa nada)
    child.sendline("terminal length 0")
    child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF], timeout=10)

    # --- Ejecutar backup ---
    copy_cmd = f"copy running-config tftp://{tftp_server}/{filename}"
    print(f"▶️ Ejecutando: {copy_cmd}")
    child.sendline(copy_cmd)

    # Manejo de prompts variados
    for _ in range(18):
        j = child.expect([
            r"Address or name of remote host\s*\[.*\]\s*:\s*$",
            r"Remote host\s*\[.*\]\s*:\s*$",
            r"Destination filename\s*\[.*\]\s*:\s*$",
            r"Source filename\s*\[.*\]\s*:\s*$",
            r"Overwrite.*\(Y/N\)|Overwrite.*\[Y/N\]|\(Y/N\)|\[Y/N\]|\(y/n\)|\[y/n\]",
            r"confirm",
            r"Are you sure.*\?",
            r"Press any key to continue",
            r"--More--",
            r"#\s*$",
            r">\s*$",
            r"%\s*Error|Error:|Invalid|Failed|No such|Timed out",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ], timeout=45)

        if j in (9, 10):
            print("✅ Backup finalizado (regresó a prompt).")
            break

        if j in (0, 1):
            child.sendline(tftp_server)
            continue

        if j == 2:
            child.sendline(filename)
            continue

        if j == 3:
            child.sendline("running-config")
            continue

        if j == 4:
            child.sendline("Y")
            continue

        if j == 5:
            child.sendline("")
            continue

        if j == 6:
            child.sendline("Y")
            continue

        if j == 7:
            child.sendline("")
            continue

        if j == 8:
            child.send(" ")
            continue

        if j == 11:
            err = (child.before or "")[-400:]
            print("❌ El equipo reportó un error durante el copy:")
            print(err)
            sys.exit(1)

        if j in (12, 13):
            continue

    else:
        print("⚠️ No pude confirmar el fin del copy (no volvió al prompt). Revisa conectividad con TFTP.")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP: {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)
