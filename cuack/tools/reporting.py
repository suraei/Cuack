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


def actualizar_reporte(domain):
    ensure_directory(domain)
    report_path = ruta_en_resultados("report.txt", domain)
    archivo_nmap_vivos = ruta_en_resultados("vivos.nmap", domain)
    ips_subdominios = extraer_hosts_vivos_de_nmap(archivo_nmap_vivos)

    # Generar la tabla de Scope fuera del bloque with para evitar duplicados
    scope_table = generar_scope_table(ips_subdominios)

    with open(report_path, "w") as report_file:  # Modificado "a" por "w" para sobrescribir el archivo cada vez
        # Escribir la cabecera del reporte
        report_file.write(f"Reporte de {domain}\n")
        report_file.write("=" * 50 + "\n\n")

        # Escribir la sección 'Scope'
        report_file.write("Scope\n")
        report_file.write(scope_table + "\n\n")

        # Si se proporciona archivo_nmap, generar y escribir la sección 'Puertos y servicios'
        if comprobar_archivo_resultados(domain, "nmap.xml"):
            detalles_nmap = parsear_nmap(ruta_en_resultados("nmap.xml", domain))
            report_file.write("Puertos y servicios\n")
            report_file.write(generar_puertos_servicios_table(detalles_nmap) + "\n\n")

        # Nueva sección para exploits encontrados
        if comprobar_archivo_resultados(domain, "exploits.json"):
            report_file.write("Posibles Exploits\n\n[!] Si quieres descargar alguno ejecuta el comando searchsploit -m {id}\n")
            exploits_path = ruta_en_resultados("exploits.json", domain)
            with open(exploits_path, "r") as exploits_file:
                exploits_data = json.load(exploits_file)
                exploits_table = PrettyTable(["Título", "ID"])
                for exploit in exploits_data:
                    exploit_title = exploit["Title"]
                    exploit_id = exploit["Path"].split("/")[-1].split(".")[0]
                    exploits_table.add_row([exploit_title, exploit_id])
                report_file.write(exploits_table.get_string() + "\n\n")

    print_file(report_path)
    print_info(f"Reporte actualizado con éxito. Puedes consultarlo en {report_path}")


