#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime
import pexpect


def sanitize_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('_')


def log(msg: str):
    print(msg, flush=True)


def prompt_any():
    # Prompt TP-Link: ...> o ...# (sin ^ para tolerar banners)
    return re.compile(r'(?m)[^\r\n]*[>#]\s*$')


def prompt_privileged():
    return re.compile(r'(?m)[^\r\n]*#\s*$')


def parse_host_ip(tag: str, fallback_ip: str):
    raw = (tag or "").strip()
    if "__" in raw:
        h, ip = raw.split("__", 1)
        return (h.strip() or "HOST", ip.strip() or fallback_ip)

    # Ej: CAMARAS-MANTA_172.16.45.46
    m = re.match(r"^(.*)_(\d{1,3}(?:\.\d{1,3}){3})$", raw)
    if m:
        return (m.group(1).strip() or "HOST", m.group(2).strip() or fallback_ip)

    return (raw if raw else "HOST", fallback_ip)


def login_ssh(host, user, password, port):
    # CLAVE: -tt fuerza tty (muchos switches lo requieren)
    ssh_cmd = (
        f"ssh -tt -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password "
        f"-o PubkeyAuthentication=no "
        f"-p {port} {user}@{host}"
    )

    log(f"[+] Conectando por SSH: {user}@{host}:{port}")
    child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=35)
    child.delaybeforesend = 0.05

    patterns = [
        re.compile(r'(?i)are you sure you want to continue connecting'),  # 0
        re.compile(r'(?i)login as:\s*$'),                                 # 1
        re.compile(r'(?i)user\s*name\s*:\s*$'),                            # 2
        re.compile(r'(?i)username\s*:\s*$'),                               # 3
        re.compile(r'(?i)login\s*:\s*$'),                                  # 4
        re.compile(r'(?i)password\s*:\s*$'),                               # 5
        prompt_any(),                                                     # 6
        pexpect.TIMEOUT,                                                  # 7
        pexpect.EOF                                                       # 8
    ]

    for _ in range(35):
        idx = child.expect(patterns, timeout=35)

        if idx == 0:
            child.sendline("yes")
            continue
        if idx in (1, 2, 3, 4):
            child.sendline(user)
            continue
        if idx == 5:
            child.sendline(password)
            continue
        if idx == 6:
            log("[+] Login OK, prompt detectado.")
            return child
        if idx == 7:
            # banner/logging largo
            child.sendline("")
            continue
        if idx == 8:
            raise RuntimeError("EOF durante login (conexión cerrada).")

    raise RuntimeError("Timeout durante login (no apareció prompt/credenciales).")


def safe_expect(child, patterns, timeout):
    """
    Expect que no imprime el dump gigante de pexpect.TIMEOUT.
    """
    try:
        return child.expect(patterns, timeout=timeout), (child.before or ""), (child.after or "")
    except pexpect.TIMEOUT:
        return None, (child.before or ""), ""
    except pexpect.EOF:
        raise RuntimeError("EOF: sesión SSH terminó inesperadamente.")


def try_enable(child) -> bool:
    """
    enable sin contraseña.
    NO falla duro si el equipo no imprime prompt (caso real que tienes).
    Retorna True si vemos #, False si no pudimos confirmar.
    """
    log("[+] Ejecutando enable (sin contraseña)...")
    child.sendline("enable")

    idx, before, after = safe_expect(
        child,
        [prompt_privileged(), re.compile(r'(?i)password\s*:\s*$'), prompt_any()],
        timeout=20
    )

    if idx == 0:
        log("[+] Enable confirmado (#).")
        return True

    if idx == 1:
        # tu caso: sin password -> ENTER vacío
        child.sendline("")
        idx2, _, _ = safe_expect(child, [prompt_privileged(), prompt_any()], timeout=20)
        if idx2 == 0:
            log("[+] Enable confirmado (#).")
            return True
        # si no confirmó, seguimos igual
        log("[WARN] Enable no se pudo confirmar (no apareció #). Continuaré igual.")
        return False

    if idx == 2:
        # ya devolvió prompt (puede ser > o #)
        txt = (after or "").strip()
        if txt.endswith("#"):
            log("[+] Ya estaba en modo privilegiado (#).")
            return True
        log("[WARN] Sigue en modo usuario (>). Continuaré y reintentaré si el comando requiere privilegio.")
        return False

    # timeout sin salida
    log("[WARN] Enable no respondió (timeout sin salida). Continuaré y validaré con el siguiente comando.")
    return False


def command_need_privilege(output: str) -> bool:
    """
    Detecta mensajes típicos de falta de privilegio/permiso.
    (TP-Link varía, así que lo hacemos amplio)
    """
    if not output:
        return False
    pat = re.compile(r'(?i)(denied|insufficient|privilege|permission|not allowed|invalid input|unrecognized|error)')
    return bool(pat.search(output))


def send_and_wait(child, cmd, timeout=120):
    """
    Envía cmd y espera:
      - prompt
      - o un OK típico (backup OK) aunque no vuelva prompt
    Devuelve (success, output_text)
    """
    log(f"[CMD] {cmd}")
    child.sendline(cmd)

    ok_patterns = [
        prompt_any(),  # 0
        re.compile(r'(?i)backup .* ok'),  # 1
        re.compile(r'(?i)start to backup'),  # 2
        re.compile(r'(?i)copy.*ok'),  # 3
    ]

    idx, before, after = safe_expect(child, ok_patterns, timeout=timeout)

    # juntamos texto visto
    out = (before or "") + (after or "")
    out = out.strip()

    if idx == 0:
        return True, out

    if idx in (1, 2, 3):
        # si vimos mensajes de backup, esperamos un poco más por prompt,
        # pero si no llega, lo tomamos como éxito (porque ya dijo OK).
        idx2, before2, after2 = safe_expect(child, [prompt_any()], timeout=40)
        out2 = ((before2 or "") + (after2 or "")).strip()
        if idx2 is not None:
            return True, (out + "\n" + out2).strip()
        return True, out  # éxito por texto OK

    # timeout sin salida
    return False, out


def run_privileged(child, cmd, timeout=150):
    """
    Ejecuta cmd. Si detecta falta de privilegio, reintenta enable y vuelve a ejecutar.
    """
    success, out = send_and_wait(child, cmd, timeout=timeout)

    # Si falló o detecta error típico de privilegio/invalid
    if (not success) or command_need_privilege(out):
        log("[WARN] Posible falta de privilegio o comando no aceptado. Reintentando enable + comando...")
        try_enable(child)
        success2, out2 = send_and_wait(child, cmd, timeout=timeout)
        return success2, (out + "\n" + out2).strip()

    return success, out


def main():
    if len(sys.argv) < 7:
        print(
            "Uso:\n"
            "  backup_tftp_tplink.py <host> <user> <pass> <port> <tftp_server> <inventory_tag>\n",
            file=sys.stderr
        )
        sys.exit(2)

    host = sys.argv[1]
    user = sys.argv[2]
    password = sys.argv[3]
    port = sys.argv[4]
    tftp_server = sys.argv[5]
    inv_tag = sys.argv[6]

    hostname, ip = parse_host_ip(inv_tag, host)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = sanitize_filename(f"{hostname}_{ip}_{ts}.cfg")

    child = None
    try:
        child = login_ssh(host, user, password, port)

        # enable requerido (pero no matamos el flujo si el equipo no responde)
        try_enable(child)

        # 1) write memory
        ok1, out1 = run_privileged(child, "copy running-config startup-config", timeout=180)
        if out1:
            log(f"[OUT] {out1}")
        if not ok1:
            log("[WARN] No se pudo confirmar el prompt tras 'copy running-config startup-config' (pero continúo).")

        # 2) backup TFTP (comando exacto que validaste)
        cmd_backup = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
        ok2, out2 = run_privileged(child, cmd_backup, timeout=260)
        if out2:
            log(f"[OUT] {out2}")

        if not ok2:
            raise RuntimeError("El backup a TFTP no pudo confirmarse (timeout sin salida/OK).")

        log("[OK] Backup completado.")
        log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")

        child.sendline("exit")
        sys.exit(0)

    except Exception as e:
        log(f"[ERROR] {e}")
        if child is not None:
            try:
                log("[DEBUG] Última salida recibida:")
                log(child.before[-1400:] if child.before else "(vacío)")
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()
