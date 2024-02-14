from prettytable import PrettyTable
from utils.utils import *

def generar_scope_table():
    scope_vivo_dir = RESULTS_DIR / "host_vivos.xml"
    scope_vivo = extraer_scope_vivo(scope_vivo_dir)
    scope_table = PrettyTable(["IPs", "Subdominios"])
    scope_table.align["Subdominios"] = "l"  # Alinea los subdominios a la izquierda

    # Iterar sobre cada IP y sus subdominios
    for ip, subdominios in scope_vivo.items():
        # Si la IP tiene subdominios, procesarlos para que cada uno esté en su propia línea
        if subdominios:
            subdominios_str = "\n".join(subdominios)  # Separar subdominios con saltos de línea
            scope_table.add_row([ip, subdominios_str])
        else:
            # Si no hay subdominios, solo añadir la IP
            scope_table.add_row([ip, ""])

        # Añadir una fila vacía para la separación visual entre IPs
        scope_table.add_row(["", ""])

    return scope_table.get_string()


def generar_puertos_servicios_table(detalles_nmap):
    table = PrettyTable(["IP", "Puerto", "Servicio", "Producto", "Detalles", "Detalles Host"])
    table.align = "l"  # Alinea todas las columnas a la izquierda

    last_ip = ""  # Variable para almacenar la última IP procesada
    for host_info in detalles_nmap:
        ip = host_info.get('host', 'N/A')
        for port_info in host_info.get('ports', []):
            puerto = f"{port_info.get('portid', 'N/A')}/{port_info.get('protocol', 'N/A')}"
            servicio = port_info['service'].get('name', 'N/A')
            producto = port_info['service'].get('product', 'N/A')
            detalles = port_info.get('detalles', 'N/A').replace("; ", "\n")  # Cambio para separar con salto de línea
            detalles_host = "; ".join([f"{hs['id']}: {hs['output']}" for hs in host_info.get('hostscripts', [])])

            # Solo agrega la IP si ha cambiado desde la última vez
            if ip != last_ip:
                table.add_row([ip, puerto, servicio, producto, detalles, detalles_host])
                last_ip = ip  # Actualiza la última IP procesada
            else:
                table.add_row(["", puerto, servicio, producto, detalles, detalles_host])
            
            # Añadir una fila vacía para separación visual después de cada puerto
            table.add_row(["", "", "", "", "", ""])

    return table.get_string()

from collections import defaultdict
from prettytable import PrettyTable

def generar_tabla_exploits(exploits_json):
    tabla = PrettyTable(["Posibles afectados", "Exploit", "ID"])
    tabla.align = "l"  # Alinea todas las columnas a la izquierda

    # Estructura para agrupar por la combinación de ip y puerto y sus respectivos exploits
    agrupados_por_ip_puerto = defaultdict(list)

    # Llenado de la estructura con datos de exploits
    for exploit in exploits_json['RESULTS_EXPLOIT']:
        for affected_host in exploit['Affected_Hosts']:
            ip_puerto = f"{affected_host['ip']}:{affected_host['port']}"
            agrupados_por_ip_puerto[ip_puerto].append((exploit['Title'], exploit['EDB-ID']))

    # Determinar grupos de IPs con los mismos exploits
    grupos = defaultdict(list)
    for ip_puerto, exploits in agrupados_por_ip_puerto.items():
        grupos[frozenset(exploits)].append(ip_puerto)

    # Añadir filas a la tabla por cada grupo de exploits
    for exploits, ips_puertos in grupos.items():
        exploits_list = list(exploits)
        ips_puertos_sorted = sorted(list(ips_puertos), key=lambda x: x.split(":")[0])  # Ordena por IP y luego por puerto

        for i, ip_puerto in enumerate(ips_puertos_sorted):
            # Para el primer ip_puerto de la lista, muestra los exploits
            if i == 0:
                for j, (exploit, edb_id) in enumerate(exploits_list):
                    if j == 0:
                        tabla.add_row([ip_puerto, exploit, edb_id])
                    else:
                        tabla.add_row(["", exploit, edb_id])
            # Para los demás ip_puerto, solo muestra el ip_puerto
            else:
                tabla.add_row([ip_puerto, "", ""])
            # Añade una separación después de cada ip_puerto
            tabla.add_row(["", "", ""])

    return tabla.get_string()


def actualizar_reporte(target):
    try:
        report_path = REPORT_DIR / f"reporte_{target}.txt"
        with open(report_path, "w") as report_file:
            report_file.write(f"Reporte de {target}\n")
            report_file.write("=" * 50 + "\n\n")

            # Sección de scope
            scope_table = generar_scope_table()
            report_file.write("Scope\n" + scope_table + "\n\n")

            # Sección de puertos y servicios
            nmap_xml_file = RESULTS_DIR / "nmap.xml"
            if nmap_xml_file.exists():
                detalles_nmap = parse_nmap_xml("nmap.xml")
                puertos_servicios_table = generar_puertos_servicios_table(detalles_nmap)
                report_file.write("Puertos y Servicios\n" + puertos_servicios_table + "\n\n")
            else:
                print_msg("El archivo nmap.xml no se encuentra en el directorio esperado.", "ERROR")

            # Sección de exploits           
            exploits_json_path = RESULTS_DIR / "exploits.json"           
            if exploits_json_path.exists():                
                with open(exploits_json_path, 'r') as json_file:
                    exploits_json = json.load(json_file)  # Carga el contenido del JSON en un diccionario
                exploits_table = generar_tabla_exploits(exploits_json)
                report_file.write("Exploits\n" + exploits_table + "\n\n")
            else:
                print_msg("El archivo exploits.json no se encuentra en el directorio esperado.", "ERROR")
        
        print_msg(f"Reporte actualizado con éxito. Puedes consultarlo en {report_path}", "SUCCESS")
    except Exception as e:
        print_msg(f"Error al actualizar el reporte: {e}", "ERROR")

