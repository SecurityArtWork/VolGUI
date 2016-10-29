#!/usr/bin/env python
import os
import sys
'''
Manage.py nos permite interatuar con el framework de DJango.
Los comandos que se suelen usar son:
	
	ARRANCAR EL SERVIDOR
	- python manage.py runserver
	- python manage.py runserver 8080
	- python manage.py runserver 0.0.0.0:8000
	
	CREAR UNA NUEVA APP
	- Crear directorio de la app --> En VolUtility es "volUtility-master/web"
	- python manage.py startapp <nombre_app>

'''


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "volgui.settings")#volgui es el directorio donde estan los settings

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
