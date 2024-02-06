import subprocess
from prettytable import PrettyTable
import re
from utils import *

def run_whatweb(ip):
    """Ejecuta whatweb en la IP dada y extrae información específica de la salida."""
    url = f"http://{ip}"
    command = ["whatweb", "-a", "3", "--colour=never",url]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        print_info(f"WhatWeb report for {url}")

        # Extraer información de la salida con chequeo de existencia
        status_code_match = re.search(r'\[([0-9]{3} [^\]]+)\]', result.stdout)
        country_match = re.search(r'Country\[([^\]]+)\]', result.stdout)
        title_match = re.search(r'Title\[([^\]]+)\]', result.stdout)
        proxy_match = re.search(r'Via-Proxy\[([^\]]+)\]', result.stdout)
        http_server_match = re.search(r'HTTPServer\[([^\]]+)\]', result.stdout)

        # Accediendo a los grupos solo si la coincidencia existe
        status_code = status_code_match.group(1) if status_code_match else "Unknown"
        country = country_match.group(1) if country_match else "Unknown"
        title = title_match.group(1) if title_match else "Unknown"
        proxy = proxy_match.group(1) if proxy_match else "Unknown"
        os_server = http_server_match.group(1) if http_server_match else "Unknown"

    except subprocess.TimeoutExpired:
        print_error(f"Timeout al ejecutar WhatWeb para la IP {ip}")
        status_code, country, title, proxy, os_server = "Error", "Error", "Error", "Error", "Error"
    except Exception as e:
        print_error(f"Error al procesar los resultados de WhatWeb para la IP {ip}: {e}")
        status_code, country, title, proxy, os_server = "Error", "Error", "Error", "Error", "Error"

    return ip, status_code, country, title, proxy, os_server

def display_table(data):
    """Muestra la información recopilada en una tabla."""
    table = PrettyTable(['IP', 'Status Code', 'Country', 'Title', 'Proxy', 'OS / Server'])
    for row in data:
        table.add_row(row)
    print(table)
