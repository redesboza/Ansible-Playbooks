#!/usr/bin/env python3
import pexpect
import sys

'''
Cisco SG (SG300/SG350/CBS) - Crear/actualizar usuario local

Mantiene la misma lógica de autenticación de tus scripts:
- Detecta prompts: 'login as:', 'User Name:', 'Password:'
- Detecta prompt de equipo: '#' o '>'

Luego ejecuta:
  configure terminal
  username <new_user> privilege <priv> password <new_password>

Uso:
  python3 create_user.py <host> <ssh_user> <ssh_password> <port> <new_user> <new_password> <privilege>
'''

if len(sys.argv) != 8:
    print("❌ Uso incorrecto:")
    print("python3 create_user.py <host> <ssh_user> <ssh_password> <port> <new_user> <new_password> <privilege>")
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = sys.argv[4]
new_user     = sys.argv[5]
new_pass     = sys.argv[6]
privilege    = sys.argv[7]

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...")

ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {port} {ssh_user}@{host}"
child = pexpect.spawn(ssh_cmd, timeout=25, encoding="utf-8")

def expect_prompt():
    """Espera prompt privilegiado '#' o no-privilegiado '>' y devuelve '#' o '>'"""
    i = child.expect([r"#\s*$", r">\s*$"])
    return "#" if i == 0 else ">"

try:
    # --- Autenticación (misma idea que tu script) ---
    while True:
        i = child.expect([
            "login as:",
            "User Name:",
            "Password:",
            r"#\s*$",
            r">\s*$",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ])

        if i == 0 or i == 1:
            child.sendline(ssh_user)
        elif i == 2:
            child.sendline(ssh_password)
        elif i == 3 or i == 4:
            break
        else:
            print("❌ No se pudo establecer sesión SSH (timeout/EOF).")
            sys.exit(1)

    prompt = expect_prompt()

    # Si entra a modo '>' (no privilegiado), intenta enable
    if prompt == ">":
        child.sendline("enable")
        k = child.expect([r"Password:", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        if k == 0:
            # En muchos casos, la clave enable es la misma o ya está configurada.
            child.sendline(ssh_password)
            child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        prompt = expect_prompt()

    if prompt != "#":
        print("⚠️ No quedé en modo privilegiado '#'. Revisa si falta enable password o privilegios.")

    print("✅ Conectado. Entrando a configuración global...")

    child.sendline("configure terminal")
    # SG suele mostrar (config)# o similar
    child.expect([r"\(config[^\)]*\)#", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    cmd = f"username {new_user} password {new_pass} privilege {privilege}"
    print(f"👤 Creando/actualizando usuario: {new_user} (priv {privilege})")
    child.sendline(cmd)

    # Espera volver a (config)# o prompt (por si el equipo responde con algo)
    child.expect([r"\(config[^\)]*\)#", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    # Salir a privilegiado
    child.sendline("end")
    child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    print("✅ Usuario configurado correctamente ✅")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error creando usuario: {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)
