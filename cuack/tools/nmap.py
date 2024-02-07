import subprocess
from utils.utils import *
from tools.reporting import *

def ejecutar_nmap(domain):
    """Ejecuta Nmap en las direcciones IP encontradas y guarda los resultados en un archivo XML."""
    nmap_file = ruta_en_resultados("nmap.xml", domain)
    vivos_file = ruta_en_resultados("vivos.nmap", domain)

    # Extraer las direcciones IP de vivos.nmap
    ips_subdominios = extraer_hosts_vivos_de_nmap(vivos_file)
    ips = list(ips_subdominios.keys())  

    # Verificar si hay direcciones IP para escanear
    if ips:
        # Construir el comando de Nmap con las IPs
        ips_para_nmap = ' '.join(ips)
        command = f"nmap -sVC -T4 --open {ips_para_nmap} -oX {nmap_file}"
        print_info("Ejecutando Nmap para analizar puertos y servicios...\n")

        # Ejecutar Nmap utilizando subprocess
        try:
            subprocess.run(command, shell=True, check=True)
            print_success(f"Análisis de Nmap completado. Resultados guardados en: {nmap_file}")
            # Llamada a generar el reporte aquí, asumiendo que vivos_file y output_file son usados para generar el reporte completo
            actualizar_reporte(domain)
        except subprocess.CalledProcessError as e:
            print_error(f"Error al ejecutar Nmap: {e}")
    else:
        print_error("No se encontraron IPs válidas para ejecutar Nmap.")
