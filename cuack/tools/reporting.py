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

def generar_tabla_exploits(exploits):
    table = PrettyTable(["Título", "ID", "Posibles afectados"])
    for exploit in exploits:
        titulo = exploit.get("Title", "")
        id_exploit = exploit.get("EDB-ID", "")
        afectados = exploit.get("Afectados", "")
        table.add_row([titulo, id_exploit, afectados])
    return table.get_string()


def generar_subdirectorios_table_ffuf(ips_subdominios):
    """
    Genera la tabla de subdirectorios a partir de los resultados de FFUF.

    :param ips_subdominios: Diccionario con las IPs como claves y listas de subdominios como valores.
    """
    table = PrettyTable(["IPs", "Subdirectorios"])
    for ip, subdominios in ips_subdominios.items():
        for subdominio in subdominios:
            table.add_row([ip, subdominio])
        # Añadir una fila en blanco después de cada IP para mejor legibilidad
            ip = ""  # Evita repetir la IP en las siguientes filas
        table.add_row(['', ''])

    return table.get_string()


def actualizar_reporte(domain):
    ensure_directory(domain)
    report_path = ruta_en_resultados("report.txt", domain)
    directorio_ffuf = ruta_en_resultados("FFUF", domain)
    ensure_directory(directorio_ffuf)
    directorio_exploits = ruta_en_resultados("exploits.json",domain)
    exploits_path = ruta_en_resultados("exploits.json", domain)

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

        # sección para exploits encontrados
        if comprobar_archivo_resultados(domain, "exploits.json") and not archivo_esta_vacio(exploits_path):
            with open(exploits_path, "r") as file:
                exploits_data = json.load(file)

            exploits_table = PrettyTable(["Título", "ID", "Posibles afectados"])
            for exploit in exploits_data:
                posibles_afectados = []
                for ip, info_host in detalles_nmap.items():
                    for port_id, info in info_host.get('puertos_servicios', {}).items():
                        puerto, _ = port_id.split("/")
                        if verificar_afectados_por_exploit(ip, port_id.split("/")[0], info['version'], exploit):
                            posibles_afectados.append(f"{ip}:{port_id}")
                if posibles_afectados:
                    exploits_table.add_row([exploit.get("Title", ""), exploit.get("EDB-ID", ""), ", ".join(posibles_afectados)])

            if posibles_afectados:
                report_file.write("Posibles Exploits\n\n")
                report_file.write(exploits_table.get_string() + "\n\n")
        else:
            print_warning("No se encontraron datos de exploits para incluir en el reporte.")




        # Nueva sección para subdirectorios encontrados con FFUF
        if verificar_resultados_ffuf():
            report_file.write("Subdirectorios encontrados con FFUF\n\n")
            subdirectorios_table = generar_subdirectorios_table_ffuf(ips_con_subdominios)
            report_file.write(subdirectorios_table + "\n\n")
        else:
            print_warning("No se encontraron subdirectorios para incluir en el reporte.")

    print_file(report_path)
    print_info(f"Reporte actualizado con éxito. Puedes consultarlo en {report_path}")
