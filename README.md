# 🐾 CuackV3

Bienvenido a CuackV3, una herramienta diseñada para la búsqueda de subdominios y la verificación de hosts vivos. 🦆💻 Este proyecto ofrece una experiencia de usuario colorida y amena.

## 🌟 Características

- **Interfaz de usuario interactiva y colorida**: Preguntas y mensajes informativos destacados con colores vibrantes.
- **Búsqueda de Subdominios**: Utiliza Amass, Assetfinder y Subfinder para encontrar subdominios de manera efectiva.
- **Comprobación de Hosts Vivos**: Emplea Nmap para determinar la accesibilidad de los hosts encontrados.
- **Resultados Organizados**: Almacena los resultados en archivos dentro de una estructura de directorios clara y ordenada.

## 📦 Instalación

### Clonar el repositorio

Para obtener el código fuente del proyecto:

```bash
git clone https://github.com/suraei/cuack.git
cd cuackv3
```

### Instalar dependencias del sistema

CuackV3 depende de varias herramientas de línea de comandos que puedes instalar usando apt en sistemas basados en Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y amass assetfinder subfinder nmap
```

### Instalar dependencias de Python

CuackV3 también utiliza algunas bibliotecas de Python especificadas en requirements.txt. Asegúrate de tener Python3 y pip instalados, y luego ejecuta:

```bash
pip3 install -r requirements.txt
```

## 🚀 Uso

Para usar CuackV3, simplemente ejecuta el script principal. El programa te guiará a través del proceso con preguntas interactivas:

```bash
python3 main.py
```

Sigue las instrucciones en pantalla para completar tu análisis de dominios o direcciones IP.
