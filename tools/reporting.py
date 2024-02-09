from prettytable import PrettyTable
from utils.utils import *
import os
import json
from collections import defaultdict


def generar_scope_table(ips_subdominios):
    """
    Genera la tabla 'Scope' con IPs y subdominios.
    """
    table = PrettyTable(["IPs", "Subdominios"])
    for ip, subdominios in ips_subdominios.items():
        if subdominios:  # Verificar si hay subdominios asociados a la IP
            # Añadir la primera fila con la primera entrada de subdominio
            table.add_row([ip, subdominios[0]])
            # Añadir filas adicionales para subdominios adicionales, sin repetir la IP
            for subdominio in subdominios[1:]:
                table.add_row(["", subdominio])
        else:
            # Añadir la IP sin subdominios
            table.add_row([ip, ""])
        # Añadir una fila en blanco para separar entre diferentes IPs
        table.add_row(['', ''])
    return table.get_string()

def generar_scope_table_simple(ips):
    """
    Genera la tabla 'Scope' solo con IPs si existe subdominios.txt.
    """
    table = PrettyTable(["IPs"])
    for ip in ips:
        table.add_row([ip])
        # Añadir una fila en blanco para separar entre diferentes IPs
        table.add_row([''])
    return table.get_string()


def generar_puertos_servicios_table(detalles_nmap):
    table = PrettyTable(["IPs", "Puertos", "Servicios", "Servidor", "Detalles", "Detalles Host"])

    for ip, info_host in detalles_nmap.items():
        puertos_servicios = info_host.get('puertos_servicios', {})
        detalles_host = info_host.get('detalles_host', '')
        detalles_host = detalles_host.split(';') if detalles_host else []  # Convertir a lista si no es None

        for port_id, info in puertos_servicios.items():
            detalles = info['detalles']
            detalles_host_row = detalles_host.pop(0) if detalles_host else ''
            table.add_row([ip, port_id, info['servicio'], info['version'], detalles, detalles_host_row])
            ip = ""  # Evita repetir la IP en las siguientes filas

        # Agrega filas vacías si quedan detalles_host sin distribuir
        while detalles_host:
            detalles_host_row = detalles_host.pop(0)
            ip = ""  # Evita repetir la IP en las siguientes filas
            table.add_row(['', '', '', '', '', detalles_host_row])

        # Agrega una fila en blanco después de cada IP
        ip = ""  # Evita repetir la IP en las siguientes filas
        table.add_row(['', '', '', '', '', ''])

    return table.get_string()

def generar_tabla_exploits(exploits_data):
    tabla = PrettyTable(["Posibles afectados", "Exploit", "ID"])

    # Estructura para agrupar por la combinación de ip y puerto y sus respectivos exploits
    agrupados_por_ip_puerto = defaultdict(list)

    # Llenado de la estructura con datos de exploits
    for exploits in exploits_data.values():
        for exploit_info in exploits:
            ip_puerto = f"{exploit_info['ip']}:{exploit_info['puerto']}"
            for exploit in exploit_info["exploits"]:
                agrupados_por_ip_puerto[ip_puerto].append((exploit["Title"], exploit["EDB-ID"]))

    # Determinar grupos de IPs con los mismos exploits
    grupos = defaultdict(list)
    for ip_puerto, exploits in agrupados_por_ip_puerto.items():
        grupos[frozenset(exploits)].append(ip_puerto)

    # Añadir filas a la tabla por cada grupo de exploits
    for exploits, ips_puertos in grupos.items():
        max_len = max(len(ips_puertos), len(exploits))
        exploits_list = list(exploits)

        for i in range(max_len):
            ip_puerto = ips_puertos[i] if i < len(ips_puertos) else ""
            exploit, edb_id = exploits_list[i] if i < len(exploits_list) else ("", "")
            tabla.add_row([ip_puerto, exploit, edb_id])

        # Separador entre grupos
        tabla.add_row(["", "", ""])

    return tabla.get_string()


def generar_tabla_subdirectorios_ffuf(dominio):
    # Ruta a la carpeta de resultados de FFUF
    ruta_resultados_ffuf = f"{dominio}/Resultados/FFUF/"

    # Verificar si la carpeta existe
    if not os.path.exists(ruta_resultados_ffuf):
        print("La carpeta de resultados de FFUF no existe.")
        return None

    # Crear una tabla para mostrar los resultados
    tabla = PrettyTable(["IP", "Subdirectorios"])

    # Obtener la lista de archivos en la carpeta
    archivos = os.listdir(ruta_resultados_ffuf)

    # Recorrer los archivos JSON
    for archivo in archivos:
        ruta_archivo = os.path.join(ruta_resultados_ffuf, archivo)
        if os.path.isfile(ruta_archivo):
            with open(ruta_archivo, 'r') as f:
                contenido = json.load(f)
                if "results" in contenido and contenido["results"]:
                    ip = contenido["results"][0]["host"]  # Obtener la IP del archivo JSON
                    subdirectorios = []
                    for resultado in contenido["results"]:
                        subdirectorio = resultado["input"]["FUZZ"]
                        if subdirectorio != "":
                            subdirectorios.append(subdirectorio)
                    # Agregar fila a la tabla después de recorrer todos los subdirectorios para una IP
                    if subdirectorios:
                        tabla.add_row([ip, "\n".join(subdirectorios)])
                        tabla.add_row(["", ""])

    return tabla.get_string()

def actualizar_reporte(domain):
    ensure_directory(domain)
    report_path = ruta_en_resultados("report.txt", domain)
    directorio_ffuf = ruta_en_resultados("FFUF", domain)
    ensure_directory(directorio_ffuf)
    directorio_exploits = ruta_en_resultados("exploits.json",domain)
    exploits_path = ruta_en_resultados("exploits.json", domain)
    # Inicializa la estructura para guardar los posibles afectados agrupados por IP
    posibles_afectados_por_exploit = defaultdict(lambda: defaultdict(list))

    # Verificar la existencia de subdominios.txt en la carpeta de resultados
    if comprobar_archivo_resultados("subdominios.txt", domain):
        # Solo se incluyen IPs en la tabla de Scope si subdominios.txt existe
        ips = obtener_ips_nmap(ruta_en_resultados("nmap.xml", domain))
        scope_table = generar_scope_table(ips)
    else:
        archivo_nmap_vivos = ruta_en_resultados("vivos.nmap", domain)
        ips_subdominios = extraer_hosts_vivos_de_nmap(archivo_nmap_vivos)
        scope_table = generar_scope_table_simple(ips_subdominios)

    with open(report_path, "w") as report_file:
        # Escribir la cabecera del reporte y la sección 'Scope'
        report_file.write(f"Reporte de {domain}\n")
        report_file.write("=" * 50 + "\n\n")
        report_file.write("Scope\n")
        report_file.write(scope_table + "\n\n")

        # Sección 'Puertos y servicios'
        if comprobar_archivo_resultados(domain, "nmap.xml"):
            detalles_nmap = parsear_nmap(ruta_en_resultados("nmap.xml", domain))
            report_file.write("Puertos y servicios\n")
            report_file.write(generar_puertos_servicios_table(detalles_nmap) + "\n\n")

        #Sección exploits
        if os.path.isfile(exploits_path):
            with open(exploits_path, "r") as exploits_file:
                exploits_data = json.load(exploits_file)

            if exploits_data:
                report_file.write("Posibles Exploits\n\n")
                report_file.write(generar_tabla_exploits(exploits_data) + "\n\n")
            else:
                print_warning("No se encontraron archivos de resultados de exploits para incluir en el reporte.")
        

        # Sección para subdirectorios encontrados con FFUF
        if verificar_resultados_ffuf(domain):
            report_file.write("Subdirectorios encontrados con FFUF\n\n")
            subdirectorios_table = generar_tabla_subdirectorios_ffuf(domain)
            report_file.write(subdirectorios_table + "\n\n")
        else:
            print_error("VA MAL EL VERIFICAR")

    print_file(report_path)
    print_info(f"Reporte actualizado con éxito. Puedes consultarlo en {report_path}")