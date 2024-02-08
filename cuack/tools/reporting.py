from prettytable import PrettyTable
from utils.utils import *
import os
import json

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
    table = PrettyTable(["IPs", "Puertos", "Servicios", "Versiones", "Detalles"])
    for ip, servicios in detalles_nmap.items():
        for puerto, info in servicios.items():
            table.add_row([
                ip,
                puerto,
                info['servicio'],
                info['version'],
                info['detalles']
            ])
            ip = ""  # Evita repetir la IP en las siguientes filas
            
        # Agrega una fila en blanco después de cada IP
        table.add_row(['', '', '', '', ''])
    return table.get_string()


def generar_subdirectorios_table_ffuf(directorio_ffuf):
    """
    Genera la tabla de subdirectorios a partir de los resultados de FFUF.
    """
    table = PrettyTable(["IPs", "Subdirectorios"])
    for archivo in os.listdir(directorio_ffuf):
        if archivo.startswith("ffuf_results_") and archivo.endswith(".json"):
            ip = archivo.replace("ffuf_results_", "").replace(".json", "")
            ruta_archivo = os.path.join(directorio_ffuf, archivo)
            try:
                with open(ruta_archivo, 'r') as f:
                    data = json.load(f)
                    for resultado in data.get("results", []):
                        url = resultado.get("url", "")
                        table.add_row([ip, url])
                    # Añadir una fila en blanco después de cada IP para mejor legibilidad
                    table.add_row(['', ''])
            except json.JSONDecodeError:
                print_error(f"Error al decodificar JSON para la IP {ip} en el archivo {archivo}")
    return table.get_string()


def actualizar_reporte(domain):
    ensure_directory(domain)
    report_path = ruta_en_resultados("report.txt", domain)
    directorio_ffuf = ruta_en_resultados("FFUF", domain)
    ensure_directory(directorio_ffuf)

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

        # Nueva sección para exploits encontrados
        if comprobar_archivo_resultados(domain, "exploits.json") and not archivo_esta_vacio(ruta_en_resultados("exploits.json", domain)):
            report_file.write("Posibles Exploits\n\n[!] Si quieres descargar alguno ejecuta el comando searchsploit -m {ID}\n")
            exploits_path = ruta_en_resultados("exploits.json", domain)
            with open(exploits_path) as exploits_file:
                exploits_data = json.load(exploits_file)
                exploits_table = PrettyTable(["Título", "ID"])
                for exploit in exploits_data:
                    exploit_title = exploit.get("Title", "")
                    exploit_id = os.path.basename(exploit.get("Path", "")).split(".")[0]
                    exploits_table.add_row([exploit_title, exploit_id])
                report_file.write(exploits_table.get_string() + "\n\n")

        # Nueva sección para subdirectorios encontrados con FFUF
        if os.path.isdir(directorio_ffuf) and len(os.listdir(directorio_ffuf)) > 0:
            report_file.write("Subdirectorios encontrados con FFUF\n\n")
            subdirectorios_table = generar_subdirectorios_table_ffuf(directorio_ffuf)
            report_file.write(subdirectorios_table + "\n\n")

    print_file(report_path)
    print_info(f"Reporte actualizado con éxito. Puedes consultarlo en {report_path}")
