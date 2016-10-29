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
¿Quieres contribuir al proyecto? ¡Fantástico!

Cualquier idea de mejora es bien recibida, `¡TE ANIMAMOS A CONTRIBUIR!`

[VolUtility]: https://github.com/kevthehermit/VolUtility

### Agradecimientos
A mis tutores:
- Francisco José Abad Cerda.
- Jaume Martín Claramonte.
- José Miguel Holguin Aparicio.

Este proyecto está basado en el proyecto [VolUtility][VolUtility], por lo que también se le agradezco a su autor:

- Kevthehermit
