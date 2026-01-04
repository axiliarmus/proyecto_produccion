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
# -b 0.0.0.0:8000: Escuchar en puerto 8000
# --access-logfile -: Mostrar logs en consola
echo "🚀 Iniciando Servidor de Producción..."
exec gunicorn -w 4 -b 0.0.0.0:8000 --access-logfile - app:app
