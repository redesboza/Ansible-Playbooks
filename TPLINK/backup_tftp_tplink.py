#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
from datetime import datetime

"""
TP-Link (JetStream/Omada) - Backup startup-config a TFTP

Comando objetivo:
  (modo privilegiado)
  copy startup-config tftp ip-address <TFTP_IP> filename <HOST>_<IP>_<TS>.cfg

Uso:
  python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>
"""

if len(sys.argv) != 7:
    print("❌ Uso: python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>")
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = int(sys.argv[4])
tftp_server  = sys.argv[5]
basename     = sys.argv[6]

ts = datetime.now().strftime("%Y%m%d-%H%M%S")
filename = f"{basename}_{ts}.cfg"

def clean(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", s)

print(f"🔎 Precheck TCP {host}:{port} ...")
try:
    sock = socket.create_connection((host, port), timeout=5)
    sock.close()
    print("✅ Puerto accesible desde el Execution Environment.")
except Exception as e:
    print(f"❌ No puedo abrir TCP a {host}:{port} desde AWX/EE. Causa: {e}")
    sys.exit(1)

print(f"🔐 Conectando por SSH v2 a {host}:{port} como {ssh_user}...")
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}")

# ✅ KEX correcto según oferta del switch:
# Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
# Elegimos group14-sha256 (mejor balance seguridad/compatibilidad).
ssh_cmd = (
    f"ssh -tt "
    f"-o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-o PubkeyAuthentication=no "
    f"-o HostKeyAlgorithms=ssh-rsa "
    f"-o KexAlgorithms=diffie-hellman-group14-sha256 "
    f"-p {port} {ssh_user}@{host}"
)

child = pexpect.spawn(ssh_cmd, timeout=30, encoding="utf-8")

PROMPT_PATTERNS = [r"#\s*$", r">\s*$", r"\]\s*$"]  # '#', '>', ']' (TP-Link)

def expect_prompt(timeout=25):
    child.timeout = timeout
    return child.expect(PROMPT_PATTERNS)

def is_privileged(idx: int) -> bool:
    return idx == 0  # '#'

try:
    # ---- LOGIN ----
    while True:
        i = child.expect([
            r"Are you sure y
