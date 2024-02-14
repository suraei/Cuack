#utils.py

from collections import defaultdict
from datetime import datetime
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import re
from time import strptime
import xml.etree.ElementTree as ET
import json
import tempfile



# Asegura la existencia del directorio de resultados
RESULTS_DIR = Path("Resultados")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR = Path("Reporte")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

class Color:
    INFO = '\033[94m[*]'
    SUCCESS = '\033[92m[!]'
    ERROR = '\033[91m[X]'
    WARNING = '\033[93m[*]'
    QUESTION = '\033[93m[?]'
    RESET = '\033[0m'

def print_msg(message, level='INFO'):
    colors = {
        'INFO': Color.INFO,
        'SUCCESS': Color.SUCCESS,
        'ERROR': Color.ERROR,
        'WARNING': Color.WARNING
    }
    print(f"{colors.get(level, Color.INFO)} {message}{Color.RESET}")

def ask_user(message):
    return input(f"{Color.QUESTION} {message}{Color.RESET} ")


def execute_tool(command, output_file=None, append_output=False, suppress_output=False, capture_output=False):
    try:
        print_msg(f"Ejecutando: {' '.join(command)}", 'INFO')

        # Ejecutar el comando sin intentar redirigir stdout a un archivo si output_file es None
        if output_file is None:
            process = subprocess.run(command, stderr=subprocess.PIPE, text=True, check=True)
        else:
            output_path = RESULTS_DIR / output_file
            with open(output_path, 'a' if append_output else 'w') as file:
                if capture_output or suppress_output:
                    # Redirigir stdout al archivo si se solicita captura o supresión
                    process = subprocess.run(command, stdout=file, stderr=subprocess.PIPE, text=True, check=True)
                else:
                    # Capturar stdout para escribirlo manualmente en el archivo
                    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                    file.write(process.stdout)
        
        print_msg(f"El comando {' '.join(command)} ha finalizado exitosamente.", 'SUCCESS')
    except subprocess.CalledProcessError as e:
        print_msg(f"Error ejecutando {' '.join(command)}: {e}", 'ERROR')


def execute_tools_in_parallel(commands, output_file, suppress_output=False):
    try:
        with ThreadPoolExecutor(max_workers=len(commands)) as executor:
            futures = [executor.submit(execute_tool, cmd, output_file, True, suppress_output) for cmd in commands]
            for future in futures:
                future.result()  # Espera a que todos los comandos finalicen
        print_msg(f"La ejecución de herramientas en paralelo ha finalizado. Resultados guardados en {output_file}.\n", 'INFO')
        clean_results(output_file)
    except Exception as e:
        print_msg(f"Error durante la ejecución en paralelo: {e}", 'ERROR')

def clean_results(file_name):
    try:
        path = RESULTS_DIR / file_name
        if not path.exists():
            print_msg(f"Archivo {file_name} no encontrado para limpiar.", 'ERROR')
            return

        unique_lines = set()
        with open(path, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("www.") and "No assets were discovered" not in line:
                    unique_lines.add(line)

        # Filtrar subdominios que son equivalentes
        filtered_lines = set()
        for line in unique_lines:
            subdomain_parts = line.split('.')
            # Eliminar subdominios tipo www1, www2, etc., si el dominio base ya está en la lista
            if subdomain_parts[0].startswith("www") and subdomain_parts[0] != "www" and len(subdomain_parts) > 2:
                base_domain = '.'.join(subdomain_parts[1:])
                if base_domain in unique_lines:
                    continue  # Omitir este subdominio
            filtered_lines.add(line)

        with open(path, 'w') as file:
            for line in sorted(filtered_lines):
                file.write(f"{line}\n")
    except Exception as e:
        print_msg(f"Error al limpiar el archivo {file_name}: {e}", 'ERROR')


def is_domain_or_url(input):
    if "http://" in input or "https://" in input or "." in input:
        return True
    return False

def is_ip_or_subnet(input):
    if "/" in input or input.count(".") == 3:
        return True
    return False



def extract_live_hosts_to_file(xml_file):
    try:
        tree = ET.parse(RESULTS_DIR / xml_file)
        root = tree.getroot()

        # Crear un archivo temporal para almacenar las IPs
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=RESULTS_DIR, mode='w+t', suffix='.txt')
        
        for host in root.findall('.//host'):
            if host.find('./status').get('state') == 'up':
                address = host.find('./address').get('addr')
                # Escribir cada dirección IP en el archivo temporal
                temp_file.write(address + '\n')
        temp_file.close()
        clean_results(temp_file)

        return temp_file.name
    except ET.ParseError as e:
        print_msg(f"Error al parsear el archivo XML: {e}", 'ERROR')
    except FileNotFoundError:
        print_msg("Archivo XML de hosts vivos no encontrado.", 'ERROR')
        return None


def check_file_existence(file_name):
    file_path = RESULTS_DIR / file_name
    return file_path.exists()


def print_titulo():
    print("""
    (\\(\\     >(.)__ <( Quack! )
    (-.-)       (___/  
    o_(")(")    
                                    https://www.github.com/suraei/cuack
    """)



def parse_nmap_xml(xml_file):
    nmap_file = RESULTS_DIR / xml_file
    nmap_info = []
    try:
        tree = ET.parse(nmap_file)
        root = tree.getroot()
        for host in root.findall('host'):
            host_info = {}
            address_info = host.find('address')
            if address_info is not None:
                host_info['host'] = address_info.get('addr')

            ports_info = []
            for port in host.findall('.//port'):
                service = port.find('service')
                product_name = service.get('product', 'N/A') if service is not None else 'N/A'
                product_name = product_name.split('/')[0].strip()
                port_info = {
                    'portid': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'service': {},
                    'scripts': []
                }

                service = port.find('service')
                if service is not None:
                    port_info['service'] = {
                        'name': service.get('name'),
                        'product': service.get('product', 'N/A'),
                        'extra_info': service.get('extrainfo', 'N/A')
                    }

                for script in port.findall('script'):
                    script_info = {
                        'id': script.get('id'),
                        'output': script.get('output'),
                        'elements': []
                    }

                    for elem in script.findall('elem'):
                        script_info['elements'].append({
                            'key': elem.get('key'),
                            'value': elem.text
                        })
                    scripts_outputs = [script for script in port_info['scripts']]
                    port_info['detalles'] = interpretar_scripts(scripts_outputs)

                    port_info['scripts'].append(script_info)
                
                ports_info.append(port_info)
            
            host_info['ports'] = ports_info

            hostscripts = host.findall('.//hostscript/script')
            hostscripts_info = []
            for script in hostscripts:
                script_info = {
                    'id': script.get('id'),
                    'output': script.get('output'),
                    'elements': []
                }
                
                for elem in script.findall('elem'):
                    script_info['elements'].append({
                        'key': elem.get('key'),
                        'value': elem.text
                    })
                
                hostscripts_info.append(script_info)

            host_info['hostscripts'] = hostscripts_info

            nmap_info.append(host_info)

    except ET.ParseError as e:
        #print(f"Verificando existencia de archivo XML en: {nmap_file}")
        print_msg(f"Error al parsear el archivo XML: {e}", 'ERROR')
    except FileNotFoundError:
        #print(f"Verificando existencia de archivo XML en: {nmap_file}")
        print_msg("Archivo XML de nmap no encontrado.", 'ERROR')
    
    return nmap_info



def interpretar_scripts(scripts):
    detalles = []
    for script in scripts:
        output = script['output']

        if 'ssl-cert' in script['id']:
            common_name_match = re.search(r'Subject: commonName=([^\\n]+)', output)
            if common_name_match and "TRAEFIK DEFAULT CERT" in common_name_match.group(1):
                detalles.append("Redirige el tráfico con TRAEFIK")

            not_valid_after_match = re.search(r'Not valid after: +(\d{4}-\d{2}-\d{2})', output)
            if not_valid_after_match:
                not_valid_after = datetime.strptime(not_valid_after_match.group(1), "%Y-%m-%d")
                if not_valid_after.date() < datetime.now().date():
                    detalles.append("Certificado Caducado")


        elif 'http-title' in script['id'] and "doesn't have a title" not in output:
            title_match = re.search(r'(.*)', output)
            if title_match:
                detalles.append(f"Título: {title_match.group(1)}")

        # Agrega aquí más reglas según sean necesarias

    return "\n".join(detalles)


def save_results(data, file_name, is_json=True):
    """
    Guarda los datos proporcionados en un archivo dentro de RESULTS_DIR.

    :param data: Los datos a guardar. Puede ser una cadena de texto o un objeto para guardar como JSON.
    :param file_name: El nombre del archivo donde se guardarán los datos.
    :param is_json: Indica si los datos se deben guardar como JSON.
    """
    output_path = RESULTS_DIR / file_name
    try:
        if is_json:
            with open(output_path, 'w') as file:
                json.dump(data, file, indent=4)
        else:
            # Verificar si los datos son una cadena de texto antes de escribir en el archivo
            if isinstance(data, str):
                with open(output_path, 'w') as file:
                    file.write(data)
            else:
                print_msg("Error: Los datos no son una cadena de texto y is_json es False.", 'ERROR')
                return
        print_msg(f"Datos guardados correctamente en {file_name}.", 'SUCCESS')
    except Exception as e:
        print_msg(f"Error al guardar los datos en {file_name}: {e}", 'ERROR')


def eliminar_archivo(ruta_archivo):
    """
    Elimina un archivo especificado por su ruta o un archivo temporal.
    
    :param ruta_archivo: Ruta del archivo a eliminar o un objeto de archivo temporal.
    """
    # Obtener la ruta del archivo si es un objeto de archivo temporal
    if hasattr(ruta_archivo, 'name'):
        ruta_archivo = ruta_archivo.name
    
    # Asegurar que ruta_archivo sea una instancia de Path
    ruta_archivo = Path(ruta_archivo)
    
    # Verificar si el archivo existe antes de intentar eliminarlo
    if ruta_archivo.exists():
        ruta_archivo.unlink()
        print_msg(f"Archivo {ruta_archivo} eliminado correctamente.", 'SUCCESS')
    else:
        print_msg(f"Archivo {ruta_archivo} no encontrado, no se realizó ninguna acción.", 'WARNING')

def get_unique_products_with_ips_ports(nmap_info):
    unique_products = {}
    for host_info in nmap_info:
        for port_info in host_info['ports']:
            product = port_info['service']['product'].split('/')[0].strip()
            if product and product != "N":
                unique_products.setdefault(product, []).append({'ip': host_info['host'], 'port': port_info['portid']})
    return unique_products

def add_affected_hosts_to_json(file, attribute, key, value, affected_hosts):
    file_path = RESULTS_DIR / file
    with open(file_path, 'r') as f:
        json_data = json.load(f)
        
    if json_data:
        for entry in json_data.get(attribute, []):
            if value and value in entry.get(key, "").lower():
                unique_affected_hosts = set((host["ip"], host["port"]) for host in entry.get("Affected_Hosts", []))
                unique_affected_hosts.update((host["ip"], host["port"]) for host in affected_hosts)
                entry["Affected_Hosts"] = [{"ip": ip, "port": port} for ip, port in unique_affected_hosts]
                
    with open(file_path, 'w') as f:
        json.dump(json_data, f, indent=4)


def extraer_scope_vivo(xml_file):
    ip_subdominios = defaultdict(set)  # Diccionario para agrupar subdominios por IP
    try:
        xml_path = RESULTS_DIR / xml_file if isinstance(xml_file, str) else xml_file
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall('host'):
            if host.find('./status').get('state') == 'up':
                address = host.find('./address').get('addr')

                for hostname in host.findall('./hostnames/hostname'):
                    if hostname.get('type') != 'PTR':  # Excluir registros PTR
                        ip_subdominios[address].add(hostname.get('name'))
    except ET.ParseError as e:
        print_msg(f"Error al parsear el archivo XML: {e}", 'ERROR')
    except FileNotFoundError:
        print_msg("Archivo XML de hosts vivos no encontrado.", 'ERROR')

    # Convertir los conjuntos de subdominios a listas para mantener la coherencia
    return {ip: list(subdominios) for ip, subdominios in ip_subdominios.items()}

def extract_unique_ips(xml_file_path):
    xml_file_path = RESULTS_DIR / xml_file_path if isinstance(xml_file_path, str) else xml_file_path
    unique_ips = set()

    try:
        if not Path(xml_file_path).is_file():
            print(f"Archivo XML '{xml_file_path}' no encontrado.")
            return None

        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                address = host.find('address')
                if address is not None:
                    ip = address.get('addr')
                    unique_ips.add(ip)

        # Crear un archivo temporal para almacenar las IPs y asegurar su eliminación automática
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt', prefix='unique_ips_', dir=str(RESULTS_DIR), newline='\n')
        temp_ips_file_path = Path(temp_file.name)  # Convertir la ruta del archivo temporal a un objeto Path
        
        for ip in unique_ips:
            temp_file.write(f"{ip}\n")
        temp_file.close()

        print(f"Archivo temporal creado en: {temp_ips_file_path} con {len(unique_ips)} IPs únicas.")
        return temp_ips_file_path
    except ET.ParseError as e:
        print(f"Error al parsear el archivo XML: {e}")
        return None