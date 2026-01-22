#!/usr/bin/env python3
import pexpect
import sys

'''
Cisco SG (SG300/SG350/CBS) - Crear/actualizar usuario local

Autenticación robusta:
- Detecta prompts: 'login as:', 'User Name:', 'Password:', y confirmación de hostkey
- Detecta prompt del equipo (privilegiado '#', o no-privilegiado '>')

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

# -tt fuerza TTY (muchos Cisco/SG lo prefieren para mostrar prompt)
ssh_cmd = (
    f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-p {port} {ssh_user}@{host}"
)
child = pexpect.spawn(ssh_cmd, timeout=35, encoding="utf-8")

def expect_prompt(timeout=35):
    """Espera prompt privilegiado '#' o no-privilegiado '>' y devuelve '#' o '>'"""
    child.timeout = timeout
    i = child.expect([r"#\s*$", r">\s*$"])
    return "#" if i == 0 else ">"


try:
    # --- Autenticación ---
    # IMPORTANTE: No hacemos expect_prompt() inmediatamente después de haber matcheado el prompt,
    # porque ese expect ya consumió el prompt. Guardamos cuál fue el prompt detectado.
    detected_prompt = None

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
        elif i == 5:
            detected_prompt = "#"
            break
        elif i == 6:
            detected_prompt = ">"
            break
        elif i == 7:
            child.sendline("")
        elif i == 8:
            child.send(" ")  # espacio para avanzar paginación
        else:
            print("❌ No se pudo establecer sesión SSH (timeout/EOF).\n" + child.before[-400:])
            sys.exit(1)

    prompt = detected_prompt

    # Enviar ENTER para refrescar el prompt (evita quedar en medio de mensajes syslog/banners)
    child.sendline("")
    prompt = expect_prompt(timeout=35)

    # Si entra a modo '>' (no privilegiado), intenta enable
    if prompt == ">":
        child.sendline("enable")
        k = child.expect([r"Password:", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        if k == 0:
            child.sendline(ssh_password)
            child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        # refresca prompt
        child.sendline("")
        prompt = expect_prompt(timeout=35)

    if prompt != "#":
        print("⚠️ No quedé en modo privilegiado '#'. Revisa enable password o privilegios del usuario SSH.")

    print("✅ Conectado. Entrando a configuración global...")

    child.sendline("configure terminal")
    child.expect([r"\(config[^\)]*\)#", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    cmd = f"username {new_user} privilege {privilege} password {new_pass}"
    print(f"👤 Creando/actualizando usuario: {new_user} (priv {privilege})")
    child.sendline(cmd)

    # Espera volver a config prompt o prompt general
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

