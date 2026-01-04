#!/bin/bash
# Script para iniciar la aplicación en modo producción en el VPS

# Activar entorno virtual si existe
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Instalar dependencias por si acaso
pip install -r requirements.txt

# Iniciar Gunicorn
# -w 4: 4 workers (bueno para VPS de 1-2 CPUs)
# -b 127.0.0.1:8000: Escuchar solo localmente (más seguro, Caddy hace el resto)
# --access-logfile -: Mostrar logs en consola
echo "🚀 Iniciando Servidor de Producción..."
exec gunicorn -w 4 -b 127.0.0.1:8000 --access-logfile - app:app
