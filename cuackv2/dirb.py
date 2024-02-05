import os
import xml.etree.ElementTree as ET
import subprocess
from concurrent.futures import ThreadPoolExecutor
from utils import print_info, print_success, print_error

def extract_ips_with_web_ports(nmap_file):
    """
    Extrae las IPs que tienen puertos web abiertos de un archivo nmap en formato XML.
    
    Args:
        nmap_file (str): Ruta al archivo nmap XML.
    
    Returns:
        list: Lista de IPs con puertos web abiertos.
    """
    web_ports = {'80', '443', '8080', '8000'}  # Define los puertos web comunes
    ips_with_web_ports = []

    tree = ET.parse(nmap_file)
    root = tree.getroot()

    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':  # Solo considera hosts activos
            ip_address = host.find('address').get('addr')
            ports = host.find('ports').findall('port')
            for port in ports:
                if port.get('protocol') == 'tcp' and port.get('portid') in web_ports and port.find('state').get('state') == 'open':
                    ips_with_web_ports.append(ip_address)
                    break  # Si encuentra un puerto web abierto, añade la IP y continúa con el siguiente host

    return ips_with_web_ports


    
def run_dirb_tool(ip, results_directory):
    """
    Ejecuta Dirb para una IP específica y guarda los resultados.
    
    Args:
        ip (str): La dirección IP para la cual ejecutar Dirb.
        results_directory (str): El directorio donde guardar los resultados.
    """
    dirb_directory = os.path.join(results_directory, 'dirb')
    os.makedirs(dirb_directory, exist_ok=True)  # Crea el directorio si no existe
    output_file = os.path.join(dirb_directory, f'{ip}.dirb')

    # Define el comando para ejecutar Dirb
    command = f"dirb http://{ip} -o {output_file}"
    
    try:
        print_info(f"Ejecutando Dirb en {ip}")
        result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        with open(output_file, "wb") as file:
            file.write(result)
        print_success(f"Escaneo de Dirb completado para {ip}. Resultados guardados en {output_file}")
    except subprocess.CalledProcessError as e:
        print_error(f"Error al ejecutar Dirb en {ip}: {e}")

def run_dirb_on_ips(ips, results_directory):
    """
    Ejecuta Dirb en paralelo para una lista de IPs.
    
    Args:
        ips (list): Lista de IPs para ejecutar Dirb.
        results_directory (str): El directorio donde guardar los resultados.
    """
    print_info("Iniciando escaneos Dirb en paralelo...")
    with ThreadPoolExecutor(max_workers=len(ips)) as executor:
        for ip in ips:
            executor.submit(run_dirb_tool, ip, results_directory)
    print_success("Todos los escaneos Dirb han finalizado.")