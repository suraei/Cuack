import os
import re
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import json

def init(autoreset=True):
    """Inicializa la salida de colores."""
    pass  # Puedes mantener esta función si es necesario

def print_info(message):
    """Imprime un mensaje informativo en azul."""
    print(f"\033[94m\n[*] {message}\033[0m")

def print_sub_info(message):
    """Imprime un mensaje informativo en azul."""
    print(f"\033[94m\t{message}\033[0m")

def print_success(message):
    """Imprime un mensaje de éxito en verde."""
    print(f"\033\n[92m[!] {message}\033[0m")

def print_error(message):
    """Imprime un mensaje de error en rojo."""
    print(f"\033[91m\n[X] {message}\033[0m")

def print_warning(message):
    """Imprime un mensaje de advertencia en amarillo."""
    print(f"\033[93m\n[*] {message}\033[0m")

def ensure_directory(domain):
    """Asegura la creación de un directorio para los resultados, basado en el dominio."""
    directory = domain if not domain.startswith("www.") else domain[4:]
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
    return directory

def is_ip(address):
    """
    Determina si la cadena dada es una dirección IP válida, incluidas las direcciones con máscara de red.
    
    :param address: La cadena que se va a verificar.
    :return: True si es una dirección IP válida, False de lo contrario.
    """
    # Separar la dirección IP y la máscara de red (si está presente)
    parts = address.split('/')
    ip_address = parts[0]  # La dirección IP está en la primera parte

    try:
        # Verificar si la dirección IP es válida
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

        
def is_valid_url(url):
    """Determina si la cadena dada parece ser una URL válida."""
    # Expresión regular para validar la URL
    url_pattern = r"^(http://|https://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{1,6}$"
    
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
                                https://www.github.com/suraei/cuack
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

def run_tool_capture_output(command):
    """Ejecuta una herramienta y captura tanto su salida estándar como de error."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        # Combina ambas salidas pero principalmente nos interesa stdout para `ffuf`
        output = result.stdout
        return output
    except subprocess.CalledProcessError as e:
        print_error(f"Error al ejecutar {command}: {e}")
        return ""


def comprobar_archivo_resultados(dominio, nombre_archivo):
    """Comprueba si un archivo existe en la carpeta 'Resultados' dentro del directorio del dominio."""
    ruta_resultados = os.path.join(dominio, "Resultados")
    archivo = os.path.join(ruta_resultados, nombre_archivo)
    
    return os.path.exists(archivo)

def extraer_hosts_vivos_de_nmap(archivo_nmap):
    """
    Extrae hosts vivos y sus IPs desde un archivo de salida de Nmap.
    Devuelve un diccionario donde las claves son las IPs y los valores son listas de subdominios asociados.
    """
    ips_subdominios = {}
    with open(archivo_nmap, "r") as archivo:
        for linea in archivo:
            if "Nmap scan report for" in linea:
                partes = linea.split()
                # Buscar IP dentro de paréntesis, que indica la presencia de un nombre de host
                if "(" in linea:
                    ip = partes[-1].strip("()")
                    subdominio = partes[4]  # El subdominio debería estar en esta posición
                else:
                    ip = partes[-1]  # Si no hay paréntesis, la IP es el último elemento
                    subdominio = None  # No hay subdominio asociado

                if ip not in ips_subdominios:
                    ips_subdominios[ip] = []

                if subdominio and subdominio != "localhost" and subdominio not in ips_subdominios[ip]:
                    ips_subdominios[ip].append(subdominio)

    return ips_subdominios


def guardar_en_archivo(contenido, archivo_destino):
    """
    Guarda el contenido dado en el archivo especificado.
    """
    with open(archivo_destino, "w") as archivo:
        for item in sorted(contenido):
            archivo.write(item + "\n")
    
def print_file(archivo):
    """
    Imprime el contenido de un archivo especificado línea por línea.
    """ 
    try:
        with open(archivo, 'r') as file:
            print("\n")
            contenido = file.read()        
            print(contenido)
    except FileNotFoundError:
        print_error(f"El archivo {archivo} no se encontró.")

def ask_user(message):
    """
    Imprime una pregunta para el usuario en color amarillo precedida por [?].
    """
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    question = f"\n{YELLOW}[?]{RESET} {YELLOW}{message}{RESET}"
    return input(question)

def parsear_ips_nmap(archivo_xml):
    """Devuelve una lista de todas las IPs encontradas en el archivo nmap.xml."""
    ips = []
    try:
        tree = ET.parse(archivo_xml)
        root = tree.getroot()
        for host in root.findall('./host'):
            if 'status' in host.attrib and host.attrib['status'] == 'up':
                address = host.find('address')
                if address is not None:
                    ips.append(address.attrib['addr'])
    except ET.ParseError:
        print_error("Error al parsear el archivo XML.")
    except FileNotFoundError:
        print_error(f"No se encontró el archivo {archivo_xml}.")
    
    return ips

def interpretar_scripts(scripts_outputs):
    """Interpreta la salida de los scripts para asignar valores a detalles basados en reglas."""
    detalles = []
    for script_output in scripts_outputs:
        if 'service name="ldap"' in script_output:
            # Buscar y procesar hostname y domain del servicio LDAP
            hostname_match = re.search(r'hostname="([^"]+)"', script_output)
            domain_match = re.search(r'Domain: ([^,]+)', script_output)
            hostname = hostname_match.group(1) if hostname_match else ''
            domain = domain_match.group(1) if domain_match else ''
            detalles.append(f"Hostname: {hostname}")
            detalles.append(f"Domain: {domain}")

    return "; ".join(detalles)

def interpretar_hostscripts(scripts_outputs):
    """Interpreta la salida de los scripts para asignar valores a detalles basados en reglas."""
    detalles = []
    for script_output in scripts_outputs:
        if script_output:  # Verifica si script_output no es None ni una cadena vacía
            lines = script_output.strip().split('\n')  # Divide las líneas de la salida del script
            for line in lines:
                # Buscar y procesar la información necesaria de cada línea
                if "OS:" in line:
                    detalles.append(line.strip())
                elif "Computer name:" in line:
                    detalles.append(line.strip())
                elif "Workgroup:" in line:
                    detalles.append(line.strip())
                elif "message_signing: disabled" in line:
                    detalles.append("Entrada al smb sin credenciales")

    return "; ".join(detalles)




def parsear_nmap(archivo_xml):
    resultado = {}
    try:
        tree = ET.parse(archivo_xml)
        root = tree.getroot()
        for host in root.findall('.//host'):
            if host.find('./status').get('state') == 'up':
                ip = host.find('./address').get('addr')
                hostscripts_outputs = []  # Inicializa la lista de salidas de hostscripts
                for hostscript in host.findall('.//hostscript'):  # Itera sobre los elementos hostscript
                    script_outputs = [script.get('output') for script in hostscript.findall('./script')]
                    #print(f"SOpts:{script_outputs}")
                    # Concatena todas las salidas de los scripts en una lista
                    hostscripts_outputs.extend(script_outputs)
                detalles_host = interpretar_hostscripts(hostscripts_outputs)  # Pasa los textos a la función
                puertos_servicios = {}
                for port in host.findall('.//port'):
                    if port.find('./state').get('state') == 'open':
                        servicio_element = port.find('./service')
                        if servicio_element is not None:
                            portid = port.get('portid') + '/' + port.get('protocol')
                            servicio = port.find('./service').get('name', 'unknown')
                            producto = port.find('./service').get('product', '')
                            version = port.find('./service').get('version', '')
                            extrainfo = port.find('./service').get('extrainfo', '')
                            scripts_outputs = [script.get('output') for script in port.findall('./script')]
                            #print(f"a:{scripts_outputs}")
                            if any("Content-Type: text/html" in script_output for script_output in scripts_outputs):
                                servicio = "http"
                            detalles = interpretar_scripts(scripts_outputs)

                            # Ajuste para 'producto' y 'version' con la condición general [A]/[B]
                            version_servidor = f"{producto} {version}".strip()
                            if '/' in version_servidor:
                                version_servidor = version_servidor.split('/')[0]

                            servicio_info = {
                                'servicio': servicio,
                                'version': version_servidor,
                                'detalles': detalles,
                                'extrainfo': extrainfo,
                            }
                            puertos_servicios[portid] = servicio_info
                resultado[ip] = {'puertos_servicios': puertos_servicios, 'detalles_host': detalles_host}
    except ET.ParseError as e:
        print_error(f"Error al parsear el archivo XML: {e}")
    except FileNotFoundError:
        print_error(f"No se encontró el archivo {archivo_xml}.")

    return resultado



def extraer_versiones_servicios_unicas(detalles_nmap):
    """
    Extrae y devuelve un conjunto de versiones únicas de servicios de los resultados de parsear_nmap.

    :param detalles_nmap: Diccionario con los detalles de parsear_nmap.
    :return: Conjunto de cadenas con las versiones únicas de los servicios.
    """
    versiones_unicas = set()
    for detalles in detalles_nmap.values():
        servicios = detalles.get('puertos_servicios', {})
        for info in servicios.values():
            version = info.get('version')
            if version:
                # Creamos una cadena que combine el servicio y la versión para facilitar la búsqueda de exploits
                identificador_servicio = f"{info['servicio']} {version}".strip()
                versiones_unicas.add(identificador_servicio)
    return versiones_unicas


import json

def archivo_esta_vacio(ruta_archivo):
    """
    Comprueba si el archivo especificado por ruta_archivo está vacío o contiene una lista JSON vacía.
    
    :param ruta_archivo: Ruta completa al archivo a verificar.
    :return: True si el archivo está vacío o contiene una lista JSON vacía, False de lo contrario.
    """
    try:
        # Verificar el tamaño del archivo directamente
        if os.path.getsize(ruta_archivo) == 0:
            return True

        # Leer el contenido del archivo
        with open(ruta_archivo, 'r') as file:
            contenido = file.read()

        # Comprobar si el contenido es una lista vacía en formato JSON
        if contenido.strip() == '[]':
            return True

        # Si el archivo es un JSON, comprobar si contiene una lista vacía
        try:
            json_content = json.loads(contenido)
            if isinstance(json_content, list) and len(json_content) == 0:
                return True
        except json.JSONDecodeError:
            pass

        return False
    except OSError as e:
        # Si hay un error al acceder al archivo, considerarlo como vacío
        return True

def no_hay_hosts_vivos(nmap_results_file):
    """
    Verifica si no hay ningún host vivo en los resultados de un escaneo Nmap.

    Args:
        nmap_results_file (str): Ruta al archivo de resultados del escaneo Nmap.

    Returns:
        bool: True si no hay hosts vivos, False de lo contrario.
    """
    with open(nmap_results_file, 'r') as f:
        for line in f:
            if '0 hosts up' in line:
                return True
    return False


def obtener_webs_nmap(nmap_xml_path):
    """
    Obtener las direcciones IP con servicio web del archivo nmap.xml.
    
    :param nmap_xml_path: Ruta al archivo nmap.xml.
    :return: Lista de direcciones IP con servicio web.
    """
    ips_con_web = set()  # Usamos un conjunto en lugar de una lista para evitar duplicados

    try:
        tree = ET.parse(nmap_xml_path)
        root = tree.getroot()

        # Recorrer los elementos del árbol XML
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                service = port.find('.//service')
                if service is not None and service.get('name', '').lower() in ['http', 'https']:
                    # Agregar la dirección IP al conjunto si tiene un servicio web (HTTP o HTTPS)
                    address = host.find('.//address').get('addr')
                    ips_con_web.add(address)  # Utilizamos add en lugar de append
    except ET.ParseError:
        print_error(f"No se pudo analizar el archivo XML: {nmap_xml_path}")

    # Convertir el conjunto nuevamente a una lista antes de devolverlo
    return list(ips_con_web)


def obtener_ips_con_subdominios(domain):
    """
    Obtiene las IPs con sus respectivos subdominios a partir de los archivos de resultados de FFUF.

    :param domain: El dominio para el que se obtendrán los resultados.
    :return: Un diccionario donde las claves son las IPs y los valores son listas de subdominios.
    """
    directorio_ffuf = ruta_en_resultados("FFUF", domain)
    ips_con_subdominios = {}

    if os.path.isdir(directorio_ffuf):
        for archivo in os.listdir(directorio_ffuf):
            if archivo.startswith("ffuf_results_") and archivo.endswith(".json"):
                ip = archivo.replace("ffuf_results_", "").replace(".json", "")
                ruta_archivo = os.path.join(directorio_ffuf, archivo)
                try:
                    with open(ruta_archivo, 'r') as f:
                        data = json.load(f)
                        subdominios = [resultado.get("url", "") for resultado in data.get("results", [])]
                        ips_con_subdominios[ip] = subdominios
                except json.JSONDecodeError:
                    print_error(f"Error al decodificar JSON para la IP {ip} en el archivo {archivo}")

    return ips_con_subdominios


def verificar_resultados_ffuf(dominio):
    # Ruta a la carpeta de resultados de FFUF
    ruta_resultados_ffuf = f"{dominio}/Resultados/FFUF/"

    # Verificar si la carpeta existe
    if not os.path.exists(ruta_resultados_ffuf):
        return False  # No hay subdirectorios si la carpeta no existe

    # Obtener la lista de archivos en la carpeta
    archivos = os.listdir(ruta_resultados_ffuf)

    # Verificar si hay al menos un archivo con resultados no vacíos
    for archivo in archivos:
        ruta_archivo = os.path.join(ruta_resultados_ffuf, archivo)
        if os.path.isfile(ruta_archivo):
            with open(ruta_archivo, 'r') as f:
                contenido = json.load(f)
                if contenido.get("results"):
                    if contenido["results"]:
                        return True  # Hay subdirectorios si al menos un archivo tiene resultados no vacíos

    return False  # No hay subdirectorios si todos los archivos tienen resultados vacíos