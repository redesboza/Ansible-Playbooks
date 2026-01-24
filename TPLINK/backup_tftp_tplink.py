#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
from datetime import datetime

"""
TP-Link (JetStream/Omada) - Backup startup-config a TFTP
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

# KEX que el switch ofrece (mejor balance)
# Their offer: group1-sha1, group14-sha256, group16-sha512
ssh_cmd = (
    f"ssh -tt "
    f"-o LogLevel=ERROR "
    f"-o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-o PubkeyAuthentication=no "
    f"-o HostKeyAlgorithms=ssh-rsa "
    f"-o KexAlgorithms=diffie-hellman-group14-sha256 "
    f"-p {port} {ssh_user}@{host}"
)

child = pexpect.spawn(ssh_cmd, timeout=40, encoding="utf-8")

# prompts típicos (incluye hostname antes del #/>/])
PROMPT_PATTERNS = [
    r"#\s*$",
    r">\s*$",
    r"\]\s*$",
    r"\S+#\s*$",
    r"\S+>\s*$",
    r"\S+\]\s*$",
]

def is_privileged_prompt(matched_index: int) -> bool:
    # Si matcheó un patrón con '#'
    # (los primeros y el 4to)
    return matched_index in (0, 3)

def wait_for_prompt(max_seconds=60):
    """
    Intenta "asentar" la sesión hasta ver prompt.
    Responde a banners, paginación, "press any key", etc.
    """
    end_time = datetime.now().timestamp() + max_seconds
    while datetime.now().timestamp() < end_time:
        child.send("\r")  # mejor que sendline en algunos equipos
        try:
            j = child.expect(
                PROMPT_PATTERNS + [
                    r"[Pp]assword:\s*$",
                    r".*'s password:\s*$",
                    r"Press any key.*",
                    r"Press Enter.*",
                    r"--More--",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ],
                timeout=8,
            )
        except pexpect.TIMEOUT:
            continue

        # prompt
        if j < len(PROMPT_PATTERNS):
            return j

        # password otra vez (a veces re-pregunta)
        if j in (len(PROMPT_PATTERNS), len(PROMPT_PATTERNS)+1):
            child.sendline(ssh_password)
            continue

        # press any key / enter
        if j in (len(PROMPT_PATTERNS)+2, len(PROMPT_PATTERNS)+3):
            child.send("\r")
            continue

        # paginación
        if j == len(PROMPT_PATTERNS)+4:
            child.send(" ")
            continue

        if j == len(PROMPT_PATTERNS)+5:  # EOF
            raise Exception("EOF antes de ver prompt. Salida:\n" + clean(child.before))

        # TIMEOUT -> sigue intentando
        continue

    raise Exception("Timeout esperando prompt estable.")

try:
    # ---- LOGIN ----
    while True:
        i = child.expect([
            r"Are you sure you want to continue connecting \(yes/no\)\?",
            r"login as:",
            r"User Name:",
            r"Username:",
            r"User:",
            r"[Pp]assword:\s*$",
            r".*'s password:\s*$",
            r"Permission denied",
            r"Unable to negotiate.*no matching key exchange method found",
            r"no matching host key type found",
            r"no matching cipher found",
            r"no matching MAC found",
            r"Connection refused",
            r"No route to host",
            r"Connection timed out",
            r"Connection closed",
            r"Could not resolve hostname",
            r"Press any key.*",
            r"Press Enter.*",
            r"--More--",
        ] + PROMPT_PATTERNS + [
            pexpect.EOF,
            pexpect.TIMEOUT,
        ], timeout=35)

        if i == 0:
            child.sendline("yes")
        elif i in (1, 2, 3, 4):
            child.sendline(ssh_user)
        elif i in (5, 6):
            child.sendline(ssh_password)
        elif i == 7:
            print("❌ Permission denied (usuario/clave incorrectos o AAA).")
            print(clean(child.before))
            sys.exit(1)
        elif i in (8, 9, 10, 11):
            print("❌ Fallo de negociación SSH. Detalle:")
            print(clean(child.before + (child.after or "")))
            sys.exit(1)
        elif i in (12, 13, 14, 15, 16):
            print("❌ Fallo de red/SSH. Detalle:")
            print(clean(child.before + (child.after or "")))
            sys.exit(1)
        elif i in (17, 18):
            child.send("\r")
        elif i == 19:
            child.send(" ")
        else:
            # si cayó en cualquier prompt pattern o ya está listo, rompemos
            if i >= 20 and i < 20 + len(PROMPT_PATTERNS):
                break
            if i == 20 + len(PROMPT_PATTERNS):  # EOF
                print("❌ EOF antes de ver prompt.")
                print("📌 Salida:")
                print(clean(child.before))
                sys.exit(1)
            if i == 21 + len(PROMPT_PATTERNS):  # TIMEOUT
                # intentamos estabilizar
                break

    # ---- ESTABILIZAR PROMPT ----
    pidx = wait_for_prompt(max_seconds=70)

    # ---- ENABLE (si aplica) ----
    if not is_privileged_prompt(pidx):
        child.sendline("enable")
        k = child.expect([
            r"[Pp]assword:\s*$",
            r".*'s password:\s*$",
        ] + PROMPT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF], timeout=15)

        if k in (0, 1):
            child.sendline(ssh_password)
            pidx = wait_for_prompt(max_seconds=40)
        else:
            pidx = wait_for_prompt(max_seconds=40)

    # paginación off (si existe)
    child.sendline("terminal length 0")
    pidx = wait_for_prompt(max_seconds=25)

    # ---- COPY ----
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}")
    child.sendline(cmd)

    for _ in range(40):
        j = child.expect([
            r"\(Y/N\)|\[(Y/N)\]|\(y/n\)|\[(y/n)\]|confirm|Are you sure.*\?",
            r"Destination filename.*:\s*$",
            r"Remote host.*:\s*$|Address or name of remote host.*:\s*$",
            r"Press any key.*|Press Enter.*",
            r"--More--",
            r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP",
        ] + PROMPT_PATTERNS + [
            pexpect.TIMEOUT,
            pexpect.EOF,
        ], timeout=90)

        # volvió a prompt => ok
        if j >= 6 and j < 6 + len(PROMPT_PATTERNS):
            print("✅ Backup finalizado (regresó a prompt).")
            break

        if j == 0:
            child.sendline("Y")
        elif j == 1:
            child.sendline(filename)
        elif j == 2:
            child.sendline(tftp_server)
        elif j == 3:
            child.send("\r")
        elif j == 4:
            child.send(" ")
        elif j == 5:
            print("❌ Error reportado por el switch durante copy:")
            print(clean(child.before))
            sys.exit(1)
        elif j == 6 + len(PROMPT_PATTERNS) + 1:  # EOF
            print("❌ EOF durante copy. Salida:")
            print(clean(child.before))
            sys.exit(1)
        else:
            # TIMEOUT: seguimos esperando
            continue
    else:
        print("⚠️ No confirmé fin del copy. Revisa TFTP y conectividad.")

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
