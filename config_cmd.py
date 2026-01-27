#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Cisco Small Business (SG/CBS) - Ejecutar comandos en modo configuración.

Uso:
  python3 config_cmd.py <host> <user> <password> <port> "<comando>"
  python3 config_cmd.py <host> <user> <password> <port> "<cmd1>; <cmd2>; <cmd3>"
  python3 config_cmd.py <host> <user> <password> <port> --interactive

Ejemplo:
  python3 config_cmd.py 172.16.45.46 ansible MiPass 11110 "ip http server"
  python3 config_cmd.py 172.16.45.46 ansible MiPass 11110 --interactive

Notas:
- Si el prompt queda en '>' se intenta 'enable' automáticamente.
- Acepta varios comandos separados por ';'.
"""

import pexpect
import sys


def die(msg: str, code: int = 1):
    print(msg)
    sys.exit(code)


def normalize_cmds(cmd_str: str):
    return [c.strip() for c in cmd_str.split(';') if c.strip()]


if len(sys.argv) < 6:
    die(
        "❌ Uso incorrecto:\n"
        "python3 config_cmd.py <host> <user> <password> <port> \"<comando>\"\n"
        "python3 config_cmd.py <host> <user> <password> <port> \"<cmd1>; <cmd2>\"\n"
        "python3 config_cmd.py <host> <user> <password> <port> --interactive"
    )

host = sys.argv[1]
user = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]
interactive = (sys.argv[5] == "--interactive")
cmd_str = "" if interactive else " ".join(sys.argv[5:]).strip()

if not interactive and not cmd_str:
    die("❌ Debes indicar al menos 1 comando o usar --interactive.")

cmds = [] if interactive else normalize_cmds(cmd_str)

print(f"🔐 Conectando a {host}:{port} como {user}...")
ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {port} {user}@{host}"
child = pexpect.spawn(ssh_cmd, timeout=25, encoding="utf-8", codec_errors="ignore")

try:
    # Login handshake
    while True:
        i = child.expect([
            "login as:",
            "User Name:",
            "Password:",
            r"[#>]\s*$",   # prompt # o > al final de línea
            pexpect.TIMEOUT,
            pexpect.EOF,
        ])

        if i in (0, 1):
            child.sendline(user)
        elif i == 2:
            child.sendline(password)
        elif i == 3:
            break
        elif i == 4:
            die("❌ TIMEOUT: No se pudo establecer sesión SSH (verifica IP/puerto/ACL).")
        else:
            die("❌ EOF: La sesión SSH se cerró inesperadamente.")

    # Si estamos en '>' intentamos subir a privilegiado
    child.sendline("")
    child.expect([r"(#|>)\s*$"])
    prompt = child.match.group(1)

    if prompt == ">":
        child.sendline("enable")
        j = child.expect(["Password:", r"#\s*$", r">\s*$", pexpect.TIMEOUT])
        if j == 0:
            # En muchos SMB no hay enable pass; probamos con el mismo password
            child.sendline(password)
            child.expect([r"#\s*$", r">\s*$"], timeout=10)
        # Verificamos si ya tenemos '#'
        child.sendline("")
        child.expect([r"(#|>)\s*$"])
        if child.match.group(1) != "#":
            die("❌ No se pudo entrar a modo privilegiado (#). Revisa enable password/políticas.")

    print("✅ Conectado. Entrando a modo configuración...")

    # Entrar a conf t
    child.sendline("configure terminal")
    child.expect([r"\(config\)#\s*$", r"#\s*$", pexpect.TIMEOUT], timeout=10)

    # Ejecutar comandos
    if interactive:
        print("\nModo interactivo: escribe comandos (uno por línea).")
        print("- Enter en blanco: termina y hace 'end'.")
        print("- Si escribes 'end'/'exit', también termina.\n")
        while True:
            try:
                line = input("CMD(config)# ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n🔸 Interrumpido por el usuario. Cerrando...")
                break

            if not line:
                break
            if line.lower() in ("end", "exit"):
                break

            child.sendline(line)
            child.expect([r"\(config[^)]*\)#\s*$", r"#\s*$", pexpect.TIMEOUT], timeout=15)
    else:
        print("▶️  Ejecutando comandos:")
        for c in cmds:
            print(f"   - {c}")
            child.sendline(c)
            # Esperamos un prompt de config o privilegiado (algunos equipos regresan #)
            child.expect([r"\(config[^)]*\)#\s*$", r"#\s*$", pexpect.TIMEOUT], timeout=15)

    # Salir
    child.sendline("end")
    child.expect([r"#\s*$", pexpect.TIMEOUT], timeout=10)

    print("✅ Listo. Comandos ejecutados correctamente.")

    child.sendline("exit")
    child.close()

except Exception as e:
    try:
        child.close(force=True)
    except Exception:
        pass
    die(f"❌ Error durante la ejecución: {e}")
