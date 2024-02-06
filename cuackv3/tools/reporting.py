from prettytable import PrettyTable
from utils.utils import *
import os

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


def generar_actualizar_reporte(domain, archivo_nmap_vivos, archivo_nmap=None):
    """
    Genera o actualiza el reporte completo con las secciones 'Scope' y, opcionalmente, 'Puertos y servicios'.
    """
    ensure_directory(domain)
    report_path = ruta_en_resultados("report.txt", domain)
    ips_subdominios = extraer_hosts_vivos_de_nmap(archivo_nmap_vivos)

    with open(report_path, "w") as report_file:
        report_file.write(f"Reporte de {domain}\n")
        report_file.write("=" * 50 + "\n\n")

        # Generar y escribir la sección 'Scope'
        report_file.write("Scope\n")
        report_file.write(generar_scope_table(ips_subdominios) + "\n\n")
        
        # Si se proporciona archivo_nmap, generar y escribir la sección 'Puertos y servicios'
        if archivo_nmap:
            detalles_nmap = parsear_nmap(archivo_nmap)
            #print(detalles_nmap)
            report_file.write("Puertos y servicios\n")
            report_file.write(generar_puertos_servicios_table(detalles_nmap) + "\n")

    print_file(report_path)

    print_info(f"Reporte generado/actualizado con éxito.Puedes consultarlo en {report_path}")


