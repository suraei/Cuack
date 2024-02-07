import os
from utils.utils import *
from tools.reporting import *

def comprobar_hosts_vivos(domain):
    """Comprueba qué hosts están vivos utilizando nmap y guarda los resultados."""

    # Guardar el directorio para los resultados
    hosts_vivos = ruta_en_resultados("vivos.nmap", domain)

    # Verificar si existe el archivo subdominios.txt en la ruta de resultados
    subdomains_file = ruta_en_resultados("subdominios.txt", domain)
    if comprobar_archivo_resultados(domain, "subdominios.txt"):
        # Si existe, usarlo en el comando de Nmap
        nmap_command = f"nmap -sn -iL {subdomains_file} -oN {hosts_vivos} 2>/dev/null"
    else:
        # Si no, usar el dominio como destino en el comando de Nmap
        nmap_command = f"nmap -sn {domain} -oN {hosts_vivos} 2>/dev/null"

    print_info("Iniciando comprobación de hosts vivos. Esto puede llevar tiempo...\n")

    # Ejecutar nmap para comprobar hosts vivos
    os.system(nmap_command)

    print_success("La comprobación de hosts vivos ha finalizado.")
    print_file(hosts_vivos)
    print_info(f"Los resultados se han guardado en {hosts_vivos}")
    actualizar_reporte(domain)



