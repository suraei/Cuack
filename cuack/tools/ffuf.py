import subprocess
import os
from utils.utils import *
from tools.reporting import *

def ejecutar_ffuf(domain):
    # Asegurar que el directorio para los resultados existe
    directorio_base = ruta_en_resultados("", domain)
    ensure_directory(directorio_base)

    # Crear/Asegurar la existencia del directorio FFUF dentro de resultados
    directorio_ffuf = os.path.join(directorio_base, "FFUF")
    ensure_directory(directorio_ffuf)

    ips_con_web = obtener_webs_nmap(ruta_en_resultados("nmap.xml", domain))
    if not ips_con_web:
        print_warning("No se encontraron IPs con servicios web.")
        return

    for ip in ips_con_web:
        print_info(f"Ejecutando FFUF en {ip}...")
        archivo_resultados = os.path.join(directorio_ffuf, f"ffuf_results_{ip}.json")
        command = [
            "ffuf",
            "-u", f"http://{ip}/FUZZ",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-o", archivo_resultados,
            "-of", "json",
            "-t", "100"
        ]

        # Ejecutar ffuf de manera segura
        try:
            subprocess.run(command, text=True, check=True)
            print_success(f"Resultados de FFUF para {ip} guardados en {archivo_resultados}")
            actualizar_reporte(domain)
        except subprocess.CalledProcessError as e:
            print_warning(f"FFUF encontró un error al ejecutarse en {ip}: {e}")
