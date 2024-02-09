from utils.utils import *
import subprocess
import json
from collections import defaultdict
from tools.reporting import *

def searchsploit(dominio):
    archivo_nmap = ruta_en_resultados("nmap.xml", dominio)
    detalles_nmap = parsear_nmap(archivo_nmap)
    resultados_exploits = defaultdict(list)

    for ip, info_host in detalles_nmap.items():
        puertos_servicios = info_host.get('puertos_servicios', {})
        for puerto, detalles in puertos_servicios.items():
            servidor = detalles.get('version', '').strip()  # Asumiendo que 'version' contiene el nombre del servidor
            if servidor:  # Solo procede si hay un servidor definido
                print_info(f"Buscando exploits para el servidor: {servidor} en {ip}:{puerto}")
                try:
                    # Realiza la búsqueda de exploits usando searchsploit
                    resultado = subprocess.run(["searchsploit", servidor, "--exclude=Denial of Service", "--json"], capture_output=True, text=True, check=True)
                    resultado_json = json.loads(resultado.stdout)
                    if resultado_json.get("RESULTS_EXPLOIT"):
                        print_success(f"Encontrados exploits para {servidor} en {ip}:{puerto}")
                        resultados_exploits[servidor].append({
                            "ip": ip,
                            "puerto": puerto,
                            "exploits": resultado_json.get("RESULTS_EXPLOIT", [])
                        })

                except subprocess.CalledProcessError as e:
                    print_error(f"Error al buscar exploits para {servidor} en {ip}:{puerto}: {e}")

    # Guarda los resultados en un archivo JSON
    exploits_path = ruta_en_resultados("exploits.json", dominio)
    with open(exploits_path, "w") as file:
        json.dump(resultados_exploits, file, indent=4)
        print_info(f"Resultados de exploits guardados en {exploits_path}")

    actualizar_reporte(dominio)