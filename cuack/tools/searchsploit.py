from utils.utils import *
import subprocess
import json
from tools.reporting import *

def searchsploit(dominio):
    """
    Busca exploits para cada versión única de servicio encontrada en el análisis Nmap de un dominio.

    :param dominio: El dominio para el cual se buscarán exploits.
    """
    archivo_nmap = ruta_en_resultados("nmap.xml", dominio)
    detalles_nmap = parsear_nmap(archivo_nmap)
    versiones_unicas = extraer_versiones_servicios_unicas(detalles_nmap)

    exploits_path = ruta_en_resultados("exploits.json", dominio)

    # Verifica si hay resultados antes de imprimir y evita repeticiones
    resultados_uniques = set()

    resultados_exploits = []

    for identificador_servicio in versiones_unicas:
        if identificador_servicio not in resultados_uniques:
            resultados_uniques.add(identificador_servicio)
            try:
                # Ejecuta searchsploit y guarda los resultados en un archivo JSON
                resultado = subprocess.run(["searchsploit", identificador_servicio, "--json"], capture_output=True, text=True)
                parsed_result = json.loads(resultado.stdout)
                if not parsed_result["RESULTS_EXPLOIT"]:
                    print_info(f"No se encontraron exploits relevantes para {identificador_servicio}.")
                else:
                    print_success(f"Posibles exploits para {identificador_servicio}:")
                    #print(json.dumps(parsed_result["RESULTS_EXPLOIT"], indent=4))
                    resultados_exploits.extend(parsed_result["RESULTS_EXPLOIT"])
            except Exception as e:
                print_error(f"Error al ejecutar searchsploit para {identificador_servicio}: {e}")

    # Guarda los resultados en un archivo JSON
    with open(exploits_path, "w") as file:
        file.write(json.dumps(resultados_exploits, indent=4))

    #Actualizamos el reporte:
    actualizar_reporte(dominio)


def procesar_resultados_searchsploit(json_file):
    """
    Procesa los resultados de searchsploit y extrae la información necesaria para el reporting.

    :param json_file: Ruta al archivo JSON generado por searchsploit.
    :return: Lista de diccionarios con la información de cada exploit.
    """
    resultados = []
    with open(json_file, 'r') as file:
        data = json.load(file)
        exploits = data.get("RESULTS_EXPLOIT", [])
        for exploit in exploits:
            titulo = exploit.get("Title", "")
            plataforma = exploit.get("Platform", "")
            puerto = exploit.get("Port", "")
            id_exploit = os.path.basename(exploit.get("Path", "")).split(".")[0]
            resultados.append({"Título": titulo, "Plataforma": plataforma, "Puerto": puerto, "ID": id_exploit})
    return resultados
