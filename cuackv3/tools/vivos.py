import os
from utils.utils import *


def guardar_hosts_vivos(domain):
    """Guarda las IPs y subdominios vivos en archivos separados."""
    archivo_nmap = ruta_en_resultados("vivos.nmap", domain)
    ips, subdominios = extraer_hosts_vivos_de_nmap(archivo_nmap)

    archivo_ips = ruta_en_resultados("ips.txt", domain)
    archivo_subdominios = ruta_en_resultados("subdominios.txt", domain)

    guardar_en_archivo(ips, archivo_ips)
    guardar_en_archivo(subdominios, archivo_subdominios)


def comprobar_hosts_vivos(domain):
    """Comprueba qué hosts están vivos utilizando nmap y guarda los resultados."""

    # Guardar el directorio para los resultados
    results_directory = ruta_en_resultados("vivos.nmap", domain)

    # Verificar si existe el archivo subdominios.txt en la ruta de resultados
    subdomains_file = ruta_en_resultados("subdominios.txt", domain)
    if comprobar_archivo_resultados(domain, subdomains_file):
        # Si existe, usarlo en el comando de Nmap
        nmap_command = f"nmap -sn -iL {subdomains_file} -oN {results_directory} 2>/dev/null"
    else:
        # Si no, usar el dominio como destino en el comando de Nmap
        nmap_command = f"nmap -sn {domain} -oN {results_directory} 2>/dev/null"

    print_info("Iniciando comprobación de hosts vivos. Esto puede llevar tiempo...")

    # Ejecutar nmap para comprobar hosts vivos
    os.system(nmap_command)

    print_success("La comprobación de hosts vivos ha finalizado.")
    print_info(f"Los resultados se han guardado en {results_directory}")
    guardar_hosts_vivos(domain)


