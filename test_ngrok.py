from pyngrok import ngrok
import time

try:
    # Kill any existing tunnels to be safe
    ngrok.kill()
    
    # Open a HTTP tunnel on the default port 80
    # <NgrokTunnel: "http://<public_sub>.ngrok.io" -> "http://localhost:80">
    http_tunnel = ngrok.connect(5000)
    print(f"NGROK_URL={http_tunnel.public_url}")
    
    # Keep it alive for a few seconds to verify
    time.sleep(2)
    ngrok.kill()
except Exception as e:
    print(f"ERROR={e}")
