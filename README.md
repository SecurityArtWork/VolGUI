# VolGUI
VolGUI es una interfaz gráfica de usuario para Volatility que permite almacenar los resultados en una base de datos y proporciona un análisis inicial de algunos de los comandos de Volatility para ayudar al analista forense a localizar, de forma más rápida, la presencia de software malicioso.
Toda la información necesaria la puedes encontrar en el siguiente enlace:

https://riunet.upv.es/handle/10251/70831

### Instalación
Para intalar VolGUI has de descargarte el software de github y posteriormente ejecutar el script `setup.sh` que permite instalar todas las dependencias necesarias para la ejecución del programa en un sistema operativo Linux Ubuntu 14.04 x64.
Para ejecutar el script hay que ser superusuario e introducir la siguiente instrucción en la interfaz de línea de comandos del sistema operativo:

```sh
$ sudo sh setup.sh
```

Posteriormente, hay que abrir el archivo `views.py`, situado en el directorio `/VolGUI/web`, y modificar la variable `path_dumps` con la ruta que va desde el directorio raíz del sistema operativo hasta el directorio `/VolGUI/web/dumps/`.

### Ejecución
Para ejecutar VolGUI hay que dirigirse al directorio VolGUI, donde se encuentra alojado el archivo `manage.py`, y ejecutar la siguiente instrucción mediante la interfaz de línea de comandos sustituyendo <IP:Puerto> por la dirección IP y el Puerto donde queremos que se conecte el cliente a través del navegador:

```sh
$ python manage.py runserver <IP:Puerto>
```

Posteriormente, Django indicará la URL que hay que introducir en el navegador del cliente para poder trabajar con VolGUI.

### Desarrollo
¿Quieres contribuir al proyecto? ¡Fantastico!

Cualquier idea de mejora es bien recibida, `¡TE ANIMAMOS A CONTRIBUIR!`

Estos son algunas tareas que quedan pendientes:
- Redactar la documentación para desarrolladores.
- Solucionar los problemas que se han detectado en la fase de pruebas.
- Ampliar la seguridad de la aplicación permitiendo que cada usuario tenga nombre y contraseña y realizar un análisis de vulnerabilidades software que permita evitar posibles ataques a la interfaz.
- Permitir al usuario que pueda añadir más paneles Command Output y Analysis Output para que pueda visualizar al mismo tiempo más cantidad de resultados de los comandos y de los analizadores.
- Incluir en la aplicación más comandos de Volatility y que se pueda introducir parámetros adicionales.
- Aumentar la eficiencia de la aplicación.
- Convertir aquellos comandos que su formato de salida es texto en tablas.
- Añadir comandos de Volatility y analizadores para Linux y MacOS.


### Agradecimientos
A mis tutores:
- Francisco José Abad Cerda.
- Jaume Martín Claramonte.
- José Miguel Holguin Aparicio.

Este proyecto está basado en el proyecto [VolUtility][VolUtility], por lo que también se le agradezco a su autor:

- Kevthehermit

[VolUtility]: https://github.com/kevthehermit/VolUtility
