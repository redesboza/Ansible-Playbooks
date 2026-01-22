#!/usr/bin/env python3

import pexpect
import sys

"""Cisco SG (SG300/SG350/CBS) - Guardar configuración (write memory)

Mantiene la misma lógica de autenticación que tu script de VLAN:
- Detecta prompts: 'login as:', 'User Name:', 'Password:'
- Detecta prompt de equipo: '#' o '>'

Luego ejecuta:
  write memory
Y responde de forma interactiva a los posibles prompts:
- ENTER cuando pida confirmar/filename
- 'Y' (o 'yes') cuando pida confirmación tipo (Y/N)
"""

# Uso: python3 write_memory.py <host> <user> <password> <port>
if len(sys.argv) != 5:
    print("❌ Uso incorrecto:")
    print("python3 write_memory.py <host> <user> <password> <port>")
    sys.exit(1)

host     = sys.argv[1]
user     = sys.argv[2]
password = sys.argv[3]
port     = sys.argv[4]

print(f"🔐 Conectando a {host}:{port} como {user}...")

ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {port} {user}@{host}"
child = pexpect.spawn(ssh_cmd, timeout=25, encoding="utf-8")

try:
    # --- Autenticación (igual enfoque que tu script actual) ---
    while True:
        i = child.expect([
            "login as:",
            "User Name:",
            "Password:",
            "#",
            ">",  # algunos SG dan prompt '>'
            pexpect.TIMEOUT,
            pexpect.EOF,
        ])

        if i == 0 or i == 1:
            child.sendline(user)
        elif i == 2:
            child.sendline(password)
        elif i == 3 or i == 4:
            print("✅ Conectado. Ejecutando 'write memory'...")
            break
        else:
            print("❌ No se pudo establecer sesión SSH (timeout/EOF).")
            sys.exit(1)

    # --- Guardar configuración ---
    child.sendline("write memory")

    # El usuario pidió específicamente: ENTER y luego Y + ENTER.
    # Lo hacemos robusto a variaciones de prompt:
    # - puede pedir primero ENTER (filename / confirm)
    # - luego (Y/N) o [yes/no]
    # - o puede guardar directo sin preguntar

    entered_once = False
    confirmed_yes = False

    for _ in range(8):
        j = child.expect([
            r"Destination filename.*\[.*\]",            # Destination filename [startup-config]?
            r"Overwrite file.*\?\s*\[.*\]",             # Overwrite file [startup-config]?
            r"\(Y/N\)",
            r"\[Y/N\]",
            r"\(y/n\)",
            r"\[y/n\]",
            r"Are you sure.*\?",                        # Are you sure...?
            r"confirm",                                 # confirm / Confirm
            "#",
            ">",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ])

        # Volvió a prompt: terminado
        if j in (8, 9):
            print("✅ Configuración guardada (write memory) ✅")
            break

        # TIMEOUT/EOF
        if j in (10, 11):
            continue

        # Si pide 'Destination filename [startup-config]?' => ENTER
        if j == 0:
            child.sendline("")
            entered_once = True
            continue

        # Si pide Overwrite => Y
        if j == 1:
            child.sendline("Y")
            confirmed_yes = True
            continue

        # Si pide (Y/N) o similares => Y
        if j in (2, 3, 4, 5, 6):
            child.sendline("Y")
            confirmed_yes = True
            continue

        # Si aparece 'confirm' sin (Y/N), muchos Cisco aceptan ENTER.
        if j == 7:
            if not entered_once:
                child.sendline("")
                entered_once = True
            else:
                child.sendline("Y")
                confirmed_yes = True
            continue

    else:
        print("⚠️ No pude confirmar que el equipo regresó a prompt; revisa la salida.")

    child.sendline("exit")
    child.close()

except Exception as e:
    print(f"❌ Error durante 'write memory': {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)
