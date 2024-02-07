from utils.utils import *
import os
from tools.reporting import *

def ejecutar_nmap(domain):
    """Ejecuta Nmap en las direcciones IP encontradas y guarda los resultados en un archivo XML."""
    nmap_file = ruta_en_resultados("nmap.xml", domain)
    vivos_file = ruta_en_resultados("vivos.nmap", domain)

    # Extraer las direcciones IP de vivos.nmap
    ips_subdominios = extraer_hosts_vivos_de_nmap(vivos_file)
    ips = list(ips_subdominios.keys())  # Solo necesitamos las claves que son las direcciones IP

    # Verificar si hay direcciones IP para escanear
    if ips:
        # Construir el comando de Nmap con las IPs
        ips_para_nmap = ' '.join(ips)
        command = f"nmap -sVC --open {ips_para_nmap} -oX {nmap_file} "
        print_info("Ejecutando Nmap para analizar puertos y servicios...\n")
        
        # Ejecutar Nmap
        os.system(command)
        
        print_success(f"Análisis de Nmap completado. Resultados guardados en: {nmap_file}")
        # Llamada a generar el reporte aquí, asumiendo que vivos_file y output_file son usados para generar el reporte completo
        actualizar_reporte(domain)
    else:
        print_error("No se encontraron IPs válidas para ejecutar Nmap.")
