import atexit
import re
import subprocess
import threading
import time


def _start_secure_tunnel(set_tunnel_url):
    """Inicia un tunel reverso para exponer la app local con HTTPS."""

    print("Intentando establecer tunel HTTPS seguro...")
    tunnel_cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ServerAliveInterval=60",
        "-R",
        "80:127.0.0.1:5000",
        "serveo.net",
    ]

    try:
        process = subprocess.Popen(
            tunnel_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
        )
        atexit.register(lambda: process.terminate())

        start_t = time.time()
        while time.time() - start_t < 15:
            line = process.stdout.readline()
            if not line:
                break

            if "Forwarding HTTP traffic from" in line:
                match = re.search(r"(https://[a-zA-Z0-9.-]+)", line)
                if match:
                    url = match.group(1)
                    set_tunnel_url(url)
                    print("=" * 64)
                    print("TUNEL HTTPS ACTIVO (Serveo)")
                    print(f"URL SEGURA: {url}")
                    print("Usa este enlace en tu celular para activar la camara.")
                    print("=" * 64)
                    break

            if "tunneled with tls termination" in line:
                match = re.search(r"(https://[a-zA-Z0-9.-]+\.lhr\.life)", line)
                if match:
                    url = match.group(1)
                    set_tunnel_url(url)
                    print("=" * 64)
                    print("TUNEL HTTPS ACTIVO (Localhost.run)")
                    print(f"URL SEGURA: {url}")
                    print("Usa este enlace en tu celular para activar la camara.")
                    print("=" * 64)
                    break
    except Exception as exc:
        print(f"No se pudo iniciar el tunel automatico: {exc}")


def maybe_start_tunnel(enabled, set_tunnel_url):
    if enabled:
        threading.Thread(
            target=_start_secure_tunnel,
            args=(set_tunnel_url,),
            daemon=True,
        ).start()


def print_startup_banner():
    print("================================================================")
    print(" INICIANDO SERVIDOR LOCAL")
    print(" Local: http://127.0.0.1:5000")
    print(" LAN:   http://0.0.0.0:5000")
    print("================================================================")
