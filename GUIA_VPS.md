# Guía de Instalación en VPS (Sin Dominio Propio)

Esta guía te permitirá subir tu proyecto a un VPS (DigitalOcean, AWS, Vultr, etc.) y tener **HTTPS seguro** para que funcione la cámara, usando un subdominio gratuito de **DuckDNS**.

## Paso 1: Obtener un nombre de dominio gratuito
1. Entra a [https://www.duckdns.org/](https://www.duckdns.org/).
2. Inicia sesión (con Google/Github).
3. En "subdomains", escribe un nombre para tu proyecto (ej: `mi-fabrica-2026`) y presiona **add domain**.
4. Copia la **IP Address** de tu VPS y pégala en el campo "current ip" de DuckDNS. Presiona **update ip**.
   * Ahora, `mi-fabrica-2026.duckdns.org` apunta a tu VPS.

## Paso 2: Preparar el VPS
Accede a tu VPS por terminal (SSH) y ejecuta:

```bash
# 1. Actualizar sistema
sudo apt update && sudo apt upgrade -y

# 2. Instalar Python y herramientas
sudo apt install python3-pip python3-venv git -y

# 3. Clonar tu proyecto (o subirlo por SFTP/FileZilla)
git clone https://github.com/tu-usuario/tu-repo.git
cd tu-repo

# 4. Crear entorno virtual e instalar dependencias
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn  # Servidor de producción
```

## Paso 3: Configurar Servidor Web (Caddy)
Usaremos **Caddy** en lugar de Nginx porque configura el HTTPS automáticamente sin tocar nada.

```bash
# 1. Instalar Caddy (Comandos para Debian/Ubuntu)
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy

# 2. Configurar Caddy (Reemplaza 'tudominio.duckdns.org' con el tuyo)
sudo caddy reverse-proxy --from tudominio.duckdns.org --to 127.0.0.1:8000
```
*Si todo sale bien, verás que Caddy activa el HTTPS. Luego puedes presionar `Ctrl+C` para detenerlo y configurarlo como servicio (opcional) o dejarlo corriendo en segundo plano.*

## Paso 4: Ejecutar tu Aplicación
En la carpeta de tu proyecto (con el entorno virtual activado):

```bash
# Ejecutar con Gunicorn (Servidor robusto)
# -w 4: Número de trabajadores (ajustar según CPU)
# -b :8000: Puerto interno (Caddy redirige aquí)
gunicorn -w 4 -b 127.0.0.1:8000 app:app
```

## Resumen
1. El usuario entra a `https://mi-fabrica-2026.duckdns.org`.
2. **Caddy** recibe la petición segura (HTTPS).
3. **Caddy** la pasa internamente a **Gunicorn** (puerto 8000).
4. **Gunicorn** ejecuta tu **Flask App**.
5. ¡La cámara funciona perfecto!
