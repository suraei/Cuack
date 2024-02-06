# Cuack: Herramienta de Análisis de Red 🌐 :duck:

**Cuack** es una herramienta avanzada de análisis de red diseñada para facilitar la exploración y el análisis de infraestructuras de red. Incorpora funcionalidades para descubrimiento de subdominios, comprobación de hosts vivos, análisis de servicios y generación de reportes detallados.

## 🚀 Características Principales

- 🌟 **Descubrimiento de Subdominios**: Utiliza herramientas líderes para encontrar subdominios relacionados con un dominio objetivo.
- 🖥 **Comprobación de Hosts Vivos**: Identifica qué hosts están activos utilizando Nmap.
- 🔍 **Análisis Detallado de Servicios**: Extrae información detallada de los servicios, incluyendo versiones de productos y configuraciones específicas.
- 📊 **Reportes fáciles**: Genera informes detallados, organizados y fáciles de entender, utilizando tablas y separaciones visuales.

## 🛠 Instalación

### Pre-requisitos

Asegúrate de tener Python 3 y las siguientes herramientas instaladas:
- Amass
- Assetfinder
- Subfinder
- Nmap

Para sistemas basados en Debian/Ubuntu, puedes instalar estas herramientas con:

```bash
sudo apt-get install amass assetfinder subfinder nmap
```
## 🛠 Pasos

### Clonar el repositorio:

```bash
git clone https://github.com/suraei/cuack.git
```

###Instalar dependencias de Python desde requirements.txt:

```bash

pip install -r requirements.txt
```

##📝 Uso

Para empezar a utilizar Cuack, ejecuta el script principal y sigue las instrucciones en pantalla:

```bash
python3 main.py
```

##🤝 Contribuciones

¡Las contribuciones son muy bienvenidas! 🎉 Si tienes ideas para mejorar Cuack o quieres añadir nuevas características, no dudes en crear un pull request o abrir un issue.

##📄 Licencia

Cuack se distribuye bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.

