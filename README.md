# Tarea 1 - Mypass
# Descripción
Mypass es un programa que permite almacenar contraseñas de forma segura y generar contraseñas seguras. El programa permite al usuario crear una cuenta, iniciar sesión, agregar contraseñas, ver contraseñas guardadas y un generador de contraseñas. Las contraseñas se almacenan de forma encriptada en una base de datos. El programa cuenta con un menú de opciones que permite al usuario navegar por las diferentes funcionalidades del programa.
# Instalación
## Requerimientos
- Python 3.11
## Pasos para la instalación
- Clonar el repositorio
```
git clone https://github.com/tareas-pruebas-sw/tarea-1
```
- Entrar al repositorio clonado
```
cd tarea-1
```
- Crear un entorno virutal
```
python3 -m venv env
```
- Activar entorno virtual
```
source env/bin/activate
```
- Instalar dependecias
```
pip3 install -r requirements.txt
```
# Cómo usar
- Para iniciar el programa ejecutar el main.py
```
python3 main.py
```
# Cómo contribuir
Cualquier forma de contribución es muy bienvenida.

## Pull Requests
En este proyecto se trabaja con GitFlow, a continuación se muestra como contribuir con un PR:

- Crear una copia del repositorio haciendo un fork.
- Clonar el fork del repositorio .
- Crear una rama desde la rama develop:
    - Para nuevas funcionalidades, el nombre de la rama debe cumplir con la estructura "feature/< branch-name >".
    - Para arreglo de bugs, el nombre de la rama debe cumplir con la estructura "bug/< branch-name >".
- Hacer los cambios en el código.
- Hacer un commit con los cambios.
- Crear un pull request para hacer un merge con la rama develop del repositorio original.
- Luego de esto revisaremos tu pull request.

## Issues
Una buena forma de contribuir al proyecto es enviar una issue detallada cuando encuentres un problema. También puedes crear una issue para proponer una nueva feature.

# Licencia
MIT License

Copyright (c) [2024] [Mypass]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
