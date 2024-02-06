import os
import re
import ipaddress
import subprocess


def init(autoreset=True):
    """Inicializa la salida de colores."""
    pass  # Puedes mantener esta función si es necesario

def print_info(message):
    """Imprime un mensaje informativo en azul."""
    print(f"\033[94m[*] {message}\033[0m")

def print_success(message):
    """Imprime un mensaje de éxito en verde."""
    print(f"\033[92m[!] {message}\033[0m")

def print_error(message):
    """Imprime un mensaje de error en rojo."""
    print(f"\033[91m[X] {message}\033[0m")

def print_warning(message):
    """Imprime un mensaje de advertencia en amarillo."""
    print(f"\033[93m[*] {message}\033[0m")

def ensure_directory(domain):
    """Asegura la creación de un directorio para los resultados, basado en el dominio."""
    directory = domain if not domain.startswith("www.") else domain[4:]
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
    return directory

def is_ip(address):
    """Determina si la cadena dada es una dirección IP válida."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def is_valid_url(url):
    """Determina si la cadena dada parece ser una URL válida."""
    # Expresión regular para validar la URL
    url_pattern = r"^(http://|https://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{1,4}$"
    
    # Comprobar si la URL coincide con el patrón
    return re.match(url_pattern, url) is not None

def write_ip_to_file(ip, file_path):
    """Escribe la dirección IP en el archivo especificado."""
    with open(file_path, 'w') as file:
        file.write(ip + '\n')
    print_info(f"La dirección IP {ip} ha sido guardada en {file_path}.")

def print_titulo():
    """Imprime un arte ASCII de un conejito y un pato con colores."""
    # Define los colores utilizando códigos de escape ANSI
    class Colors:
        YELLOW = '\033[93m'
        WHITE = '\033[97m'
        RESET = '\033[0m'

    # Dibuja el conejito y el pato con colores
    arte = f"""
{Colors.WHITE}   (\\(\\    {Colors.YELLOW}  >(.)__ <( Quack! )
{Colors.WHITE}   (-.-)    {Colors.YELLOW}    (___/  
{Colors.WHITE}  o_(")("){Colors.RESET}
    """
    print(arte)

def guardar_resultados(nombre_archivo, contenido):
    """Guarda el contenido en un archivo con el nombre especificado."""
    with open(nombre_archivo, "w") as file:
        file.write(contenido)

import re

def eliminar_duplicados(archivo):
    """Elimina duplicados de un archivo y sobrescribe el mismo archivo con los resultados únicos."""
    unique_items = set()
    with open(archivo, "r") as file:
        lines = file.readlines()
        for line in lines:
            item = line.strip()
            if item:
                # Elimina el prefijo "www" seguido de números si está presente
                item = re.sub(r"^www\d*\.", "", item)
                unique_items.add(item)
    # Eliminar la línea "No assets were discovered" si existe
    if "No assets were discovered" in unique_items:
        unique_items.remove("No assets were discovered")
                    
    with open(archivo, "w") as file:
        for item in sorted(unique_items):
            file.write(item + "\n")

def ensure_directory(directory):
    """Asegura la creación de un directorio si no existe."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def ruta_en_resultados(nombre_txt, domain):
    """Guarda el archivo en la carpeta 'Resultados' dentro del directorio del dominio."""
    results_directory = os.path.join(os.getcwd(), domain, "Resultados")
    ensure_directory(results_directory)  # Asegura que exista la carpeta 'Resultados'
    
    # Une el nombre del archivo con la ruta completa
    ruta_completa = os.path.join(results_directory, nombre_txt)
    return ruta_completa

def obtener_dominio_desde_url(user_input):
    """Obtiene el dominio desde una URL eliminando el protocolo (http:// o https://)."""
    # Verificar si user_input comienza con "http://" o "https://"
    if user_input.startswith("http://") or user_input.startswith("https://"):
        # Utiliza una expresión regular para encontrar el dominio
        match = re.search(r"(?<=://)([^/]+)", user_input)
        if match:
            dominio = match.group(0)
            # Si el dominio comienza con "www.", también lo eliminamos
            if dominio.startswith("www."):
                dominio = dominio[4:]
            return dominio
    return user_input


def run_tool(command, output_file):
    """Ejecuta una herramienta de línea de comandos y guarda su salida en un archivo."""
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        with open(output_file, "a") as file:
            file.write(result.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print_error(f"Error al ejecutar {command.split()[0]}: {e}")


def comprobar_archivo_resultados(dominio, nombre_archivo):
    """Comprueba si un archivo existe en la carpeta 'Resultados' dentro del directorio del dominio."""
    ruta_resultados = os.path.join(dominio, "Resultados")
    archivo = os.path.join(ruta_resultados, nombre_archivo)
    
    return os.path.exists(archivo)

def extraer_hosts_vivos_de_nmap(archivo_nmap):
    """
    Extrae hosts vivos y sus IPs desde un archivo de salida de Nmap.
    Devuelve dos conjuntos: uno de IPs y otro de subdominios.
    """
    ips = set()
    subdominios = set()
    with open(archivo_nmap, "r") as archivo:
        for linea in archivo:
            if "Nmap scan report for" in linea:
                partes = linea.split()
                ip = partes[-1].strip("()")
                host = partes[-2] if partes[-2] != ip else None
                ips.add(ip)
                if host and host != "localhost":
                    subdominios.add(host)
    return ips, subdominios

def guardar_en_archivo(contenido, archivo_destino):
    """
    Guarda el contenido dado en el archivo especificado.
    """
    with open(archivo_destino, "w") as archivo:
        for item in sorted(contenido):
            archivo.write(item + "\n")
    print_info(f"Guardado en {archivo_destino}")