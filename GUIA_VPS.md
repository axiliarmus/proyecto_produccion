# Guía de Instalación en VPS (Sin Dominio Propio)

Esta guía te permitirá subir tu proyecto a un VPS (DigitalOcean, AWS, Vultr, etc.) y tener **HTTPS seguro** para que funcione la cámara, usando un subdominio gratuito de **DuckDNS**.

## 🛑 Paso 0: ¡Importante! Liberar el puerto 80
Si al entrar a tu IP ves "Welcome to Nginx", debes detenerlo obligatoriamente.

Ejecuta esto en tu VPS:
```bash
# Detener Nginx y evitar que inicie solo
sudo systemctl stop nginx
sudo systemctl disable nginx

# Si tienes Apache, deténlo también
sudo systemctl stop apache2
sudo systemctl disable apache2
```

## Paso 1: Obtener un nombre de dominio gratuito
1. Entra a [https://www.duckdns.org/](https://www.duckdns.org/).
2. Inicia sesión.
3. Crea un subdominio (ej: `mi-fabrica-2026`) y apúntalo a la **IP de tu VPS**.

## Paso 2: Instalar y Configurar Caddy (Modo Permanente)
Usaremos el archivo de configuración oficial para que el sitio no se caiga al cerrar la consola.

### 1. Instalar Caddy
```bash
sudo apt update
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

### 2. Editar el archivo Caddyfile
Abre el archivo de configuración:
```bash
sudo nano /etc/caddy/Caddyfile
```

Borra todo lo que hay y pega esto (cambia el dominio por el tuyo):

```caddy
mi-fabrica-2026.duckdns.org {
    reverse_proxy 127.0.0.1:8000
}
```

*   Guarda con `Ctrl+O`, `Enter`.
*   Sal con `Ctrl+X`.

### 3. Reiniciar Caddy para aplicar cambios
```bash
sudo systemctl restart caddy
```

## 🚑 Solución de Problemas (Troubleshooting)

### Error: "Job for caddy.service failed"
Esto significa que Caddy no pudo iniciar. Sigue estos pasos para arreglarlo:

**1. Ver el error real:**
Ejecuta este comando para ver qué pasó:
```bash
sudo journalctl -u caddy --no-pager | tail -n 20
```

**2. Causa Probable A: Error de escritura en Caddyfile**
Asegúrate de que el archivo `/etc/caddy/Caddyfile` esté bien escrito.
*   Verifica que pusiste tu dominio real.
*   Verifica que las llaves `{ }` están bien puestas.
*   Valida el archivo con: `caddy validate --config /etc/caddy/Caddyfile`

**3. Causa Probable B: El puerto 80 sigue ocupado**
A veces Nginx no se muere del todo. Ejecuta esto para ver quién usa el puerto:
```bash
sudo lsof -i :80
```
Si ves `nginx` o `apache2` en la lista, mátalos con:
```bash
sudo killall nginx
sudo killall apache2
```
Y luego intenta reiniciar Caddy de nuevo: `sudo systemctl restart caddy`

## Paso 3: Preparar tu Aplicación
```bash
# Clonar y preparar entorno
git clone https://github.com/tu-usuario/tu-repo.git
cd tu-repo
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn
```

## Paso 4: Iniciar la Aplicación (Modo Servicio)
Para que tu app no se cierre, usa `tmux` o crea un servicio, pero la forma rápida es usar el script en segundo plano:

```bash
# Dar permisos al script
chmod +x start_production.sh

# Ejecutar en segundo plano con nohup
nohup ./start_production.sh > logs.txt 2>&1 &
```
