#!/usr/bin/env python3
import pexpect
import sys

'''
Cisco SG (SG300/SG350/CBS) - Eliminar usuario local

Autenticación robusta:
- Detecta prompts: 'login as:', 'User Name:', 'Username:', 'Password:', hostkey (yes/no)
- Detecta prompt del equipo (privilegiado '#', o no-privilegiado '>')

Luego ejecuta:
  configure terminal
  no username <del_user>

Uso:
  python3 delete_user.py <host> <ssh_user> <ssh_password> <port> <del_user>
'''

if len(sys.argv) != 6:
    print("❌ Uso incorrecto:")
    print("python3 delete_user.py <host> <ssh_user> <ssh_password> <port> <del_user>")
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = sys.argv[4]
del_user     = sys.argv[5]

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...")

# -tt fuerza TTY (muchos Cisco/SG lo prefieren)
ssh_cmd = (
    f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-p {port} {ssh_user}@{host}"
)
child = pexpect.spawn(ssh_cmd, timeout=35, encoding="utf-8")

def expect_prompt(timeout=35):
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
        elif i == 5:
            break
        elif i == 6:
            break
        elif i == 7:
            child.sendline("")
        elif i == 8:
            child.send(" ")
        else:
            print("❌ No se pudo establecer sesión SSH (timeout/EOF).\n" + child.before[-400:])
            sys.exit(1)

    # Refrescar prompt (por banners/syslog)
    child.sendline("")
    prompt = expect_prompt(timeout=35)

    # Si entra a modo '>' (no privilegiado), intenta enable
    if prompt == ">":
        child.sendline("enable")
        k = child.expect([r"Password:", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        if k == 0:
            child.sendline(ssh_password)
            child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])
        child.sendline("")
        prompt = expect_prompt(timeout=35)

    if prompt != "#":
        print("⚠️ No quedé en modo privilegiado '#'. Revisa enable password o privilegios del usuario SSH.")

    print("✅ Conectado. Entrando a configuración global...")

    child.sendline("configure terminal")
    child.expect([r"\(config[^\)]*\)#", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    cmd = f"no username {del_user}"
    print(f"🗑️ Eliminando usuario: {del_user}")
    child.sendline(cmd)

    # Espera volver a (config)# o prompt general
    child.expect([r"\(config[^\)]*\)#", r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    # Salir a privilegiado
    child.sendline("end")
    child.expect([r"#\s*$", r">\s*$", pexpect.TIMEOUT, pexpect.EOF])

    print("✅ Usuario eliminado (si existía) ✅")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error eliminando usuario: {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)
