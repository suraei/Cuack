import os
import xml.etree.ElementTree as ET
import subprocess
from concurrent.futures import ThreadPoolExecutor
from utils import *


    
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
        print_warning(f"Escaneo de Dirb completado para {ip}. Resultados guardados en {output_file}")
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
    print_info("Todos los escaneos Dirb han finalizado.")