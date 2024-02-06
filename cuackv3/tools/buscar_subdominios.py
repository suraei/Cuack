import subprocess
from concurrent.futures import ThreadPoolExecutor
import os
from utils.utils import *


def buscar_subdominios(url):
    """Encuentra subdominios utilizando varias herramientas y guarda los resultados."""
    tools = [
        f"amass enum -d {url}",
        f"assetfinder --subs-only {url}",
        f"subfinder -d {url}"
    ]
    
    subdominios = ruta_en_resultados("subdominios.txt", url)

    if comprobar_archivo_resultados(url, "subdominios.txt"):
        os.remove(subdominios)  # Asegura que el archivo esté vacío antes de comenzar

    print_info("Iniciando la búsqueda de subdominios. Esto puede tardar un poco...")

    with ThreadPoolExecutor(max_workers=len(tools)) as executor:
        for tool in tools:
            print_info(f"Ejecutando: {tool}")
            executor.submit(run_tool, tool, subdominios)

    eliminar_duplicados(subdominios)  # Elimina duplicados en el archivo de salida

    print_success("La búsqueda de subdominios ha finalizado.")
    print_info(f"Los resultados se han guardado en {subdominios}")