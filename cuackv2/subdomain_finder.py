import subprocess
from concurrent.futures import ThreadPoolExecutor
import os
from utils import print_info, print_success, print_error

def run_tool(command, output_file):
    """Ejecuta una herramienta de línea de comandos y guarda su salida."""
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        with open(output_file, "a") as file:
            file.write(result.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print_error(f"Error al ejecutar {command.split()[0]}: {e}")

def find_subdomains(domain, results_directory):
    """Encuentra subdominios utilizando varias herramientas de forma paralela."""
    tools = [
        f"amass enum -d {domain}",
        f"assetfinder --subs-only {domain}",
        f"subfinder -d {domain}"
    ]

    output_file = os.path.join(results_directory, "subdominios.txt")
    if os.path.exists(output_file):
        os.remove(output_file)  # Asegura que el archivo esté vacío antes de comenzar

    print_info("Iniciando la búsqueda de subdominios. Esto puede tardar un poquito...")

    with ThreadPoolExecutor(max_workers=len(tools)) as executor:
        for tool in tools:
            print_info(f"Ejecutando: {tool}")
            executor.submit(run_tool, tool, output_file)

    # Elimina duplicados en el archivo de salida
    unique_subdomains = set()
    with open(output_file, "r") as file:
        lines = file.readlines()
        for line in lines:
            domain = line.strip()
            if domain and not domain.startswith("www.") and not domain.startswith("http"):
                unique_subdomains.add(domain)

    with open(output_file, "w") as file:
        for domain in sorted(unique_subdomains):
            file.write(domain + "\n")

    print_info("La búsqueda de subdominios ha finalizado.")
    print_info(f"Se encontraron {len(unique_subdomains)} subdominios únicos.")
    print_info(f"Los resultados se han guardado en {output_file}")
