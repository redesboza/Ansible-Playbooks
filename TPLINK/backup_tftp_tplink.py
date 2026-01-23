#!/usr/bin/env python3
import pexpect
import sys
import re
from datetime import datetime

"""
TP-Link (JetStream/Omada Switch) - Backup startup-config a TFTP

Comando objetivo:
  (modo privilegiado)
  copy startup-config tftp ip-address <TFTP_IP> filename <HOST>_<IP>_<TS>.cfg

Uso:
  python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>

Notas:
- Autenticación robusta (login as/User Name/Username/Password, hostkey yes/no)
- Fuerza TTY con ssh -tt
- Intenta entrar a enable (si está en modo user)
- IMPORTANTE: Fuerza algoritmos SSH legacy (ssh-rsa / dh-group14-sha1 / dh-group1-sha1) para compatibilidad con switches.
"""

if len(sys.argv) != 7:
    print("❌ Uso: python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>")
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = sys.argv[4]
tftp_server  = sys.argv[5]
basename     = sys.argv[6]

ts = datetime.now().strftime("%Y%m%d-%H%M%S")
filename = f"{basename}_{ts}.cfg"

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...")
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}")

# ✅ SSH v2 (por defecto), pero habilitamos algoritmos legacy para compatibilidad (TP-Link suele requerir ssh-rsa / DH sha1)
ssh_cmd = (
    f"ssh -tt "
    f"-o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-o PubkeyAuthentication=no "
    f"-o HostKeyAlgorithms=+ssh-rsa "
    f"-o PubkeyAcceptedAlgorithms=+ssh-rsa "
    f"-o KexAlgorithms=+diffie-hellman-group14-sha1,+diffie-hellman-group1-sha1 "
    f"-p {port} {ssh_user}@{host}"
)

# Si algún modelo te falla por cipher/MAC, descomenta estas opciones:
# ssh_cmd = (
#     f"ssh -tt "
#     f"-o StrictHostKeyChecking=no "
#     f"-o UserKnownHostsFile=/dev/null "
#     f"-o PreferredAuthentications=password,keyboard-interactive "
#     f"-o PubkeyAuthentication=no "
#     f"-o HostKeyAlgorithms=+ssh-rsa "
#     f"-o PubkeyAcceptedAlgorithms=+ssh-rsa "
#     f"-o KexAlgorithms=+diffie-hellman-group14-sha1,+diffie-hellman-group1-sha1 "
#     f"-o Ciphers=aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc "
#     f"-o MACs=hmac-sha1,hmac-sha1-96,hmac-md5 "
#     f"-p {port} {ssh_user}@{host}"
# )

child = pexpect.spawn(ssh_cmd, timeout=60, encoding="utf-8")

# Prompts típicos (algunos TP-Link usan ']' o similar)
PROMPT_PATTERNS = [r"#\s*$", r">\s*$", r"\]\s*$"]

def expect_prompt(timeout=45):
    child.timeout = timeout
    return child.expect(PROMPT_PATTERNS)

def is_privileged(prompt_index: int) -> bool:
    return prompt_index == 0  # '#'

try:
    # --- Autenticación ---
    while True:
        i = child.expect([
            r"Are you sure you want to continue connecting \(yes/no\)\?",
            r"login as:",
            r"User Name:",
            r"Username:",
            r"Password:",
            r"Press any key to continue",
            r"--More--",
            r"#\s*$",
            r">\s*$",
            r"\]\s*$",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ])

        if i == 0:
            child.sendline("yes")
        elif i in (1, 2, 3):
            child.sendline(ssh_user)
        elif i == 4:
            child.sendline(ssh_password)
        elif i == 5:
            child.sendline("")
        elif i == 6:
            child.send(" ")
        elif i in (7, 8, 9):
            break
        else:
            print("❌ No se pudo establecer sesión SSH (timeout/EOF).")
            sys.exit(1)

    # Refrescar prompt por banners/syslog
    child.sendline("")
    pidx = expect_prompt(timeout=45)

    # Entrar a modo privilegiado si no está en '#'
    if not is_privileged(pidx):
        child.sendline("enable")
        k = child.expect([r"Password:", r"#\s*$", r">\s*$", r"\]\s*$", pexpect.TIMEOUT, pexpect.EOF], timeout=20)
        if k == 0:
            # muchos equipos usan la misma contraseña para enable
            child.sendline(ssh_password)
            child.expect([r"#\s*$", r">\s*$", r"\]\s*$", pexpect.TIMEOUT, pexpect.EOF], timeout=20)
        child.sendline("")
        pidx = expect_prompt(timeout=20)

    if not is_privileged(pidx):
        print("⚠️ No quedé en modo privilegiado (#). El comando puede fallar si tu usuario no tiene permisos.")

    # Desactivar paginación (si no existe, no pasa nada)
    child.sendline("terminal length 0")
    child.expect(PROMPT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF], timeout=10)

    # --- Ejecutar backup ---
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}")
    child.sendline(cmd)

    for _ in range(25):
        j = child.expect([
            r"\(Y/N\)|\[(Y/N)\]|\(y/n\)|\[(y/n)\]|confirm|Are you sure.*\?",
            r"Destination filename.*:\s*$",
            r"Remote host.*:\s*$|Address or name of remote host.*:\s*$",
            r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP",
            r"#\s*$",
            r">\s*$",
            r"\]\s*$",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ], timeout=90)

        if j in (4, 5, 6):
            print("✅ Backup finalizado (regresó a prompt).")
            break

        if j == 0:
            child.sendline("Y")
        elif j == 1:
            child.sendline(filename)
        elif j == 2:
            child.sendline(tftp_server)
        elif j == 3:
            err = (child.before or "")[-800:]
            err = re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", err)
            print("❌ El equipo reportó error durante el copy:")
            print(err)
            sys.exit(1)
        else:
            continue
    else:
        print("⚠️ No pude confirmar el fin del copy (no volvió al prompt). Revisa conectividad con TFTP.")

    child.sendline("exit")
    child.close()
    sys.exit(0)

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP en TP-Link: {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)

    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)
