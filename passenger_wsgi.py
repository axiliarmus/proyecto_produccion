import sys
import os

# Ruta absoluta a tu proyecto
project_home = '/home/mktesjiv/public_html/proyecto_produccion'

# Agregar ruta al sys.path
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Activar entorno virtual
activate_this = '/home/mktesjiv/virtualenv/public_html/proyecto_produccion/3.12/bin/activate_this.py'
with open(activate_this) as file_:
    exec(file_.read(), dict(__file__=activate_this))

# Importar la app Flask
from app import app as application
