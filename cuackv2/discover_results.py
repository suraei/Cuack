import xml.etree.ElementTree as ET
from prettytable import PrettyTable
import os
from utils import print_info, print_success, print_error

def parse_nmap_scan_results(nmap_scan_file):
    ip_subdomains = {}
    with open(nmap_scan_file, 'r') as file:
        for line in file:
            if "Nmap scan report for" in line:
                parts = line.strip().split()
                subdomain = parts[4]
                ip = parts[-1].strip('()')
                if ip not in ip_subdomains:
                    ip_subdomains[ip] = []
                ip_subdomains[ip].append(subdomain)
    return ip_subdomains

def parse_light_nmap_xml(xml_file):
    ip_services = {}
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for host in root.findall('.//host'):
        ip_address = host.find("address[@addrtype='ipv4']").get("addr")
        ip_services[ip_address] = []
        for port in host.findall('.//port'):
            service_details = {
                'port': f"{port.get('portid')}/{port.get('protocol')}",
                'service': 'unknown',
                'version': '',
                'details': ''
            }
            service = port.find('service')
            if service is not None:
                service_details['service'] = service.get('name', 'unknown')
                service_details['version'] = service.get('product', '') + " " + service.get('version', '').strip()

                # Buscar título HTTP
                http_title = port.find(".//script[@id='http-title']")
                if http_title is not None:
                    title_output = http_title.get('output')
                    if title_output and "doesn't have a title" not in title_output:
                        service_details['details'] += f"[*] {title_output} "

                # Buscar certificado TRAEFIK DEFAULT CERT
                ssl_cert_script = port.find(".//script[@id='ssl-cert']")
                if ssl_cert_script is not None:
                    ssl_output = ssl_cert_script.get('output')
                    if "TRAEFIK DEFAULT CERT" in ssl_output:
                        service_details['details'] += "[!] Redirecciona el tráfico "

                # Nueva condición para vrml-multi-use y HTTP/1.1 200 OK
                if service_details['service'] == 'vrml-multi-use':
                    for script in port.findall('.//script'):
                        if script.get('output') and "HTTP/1.1 200 OK" in script.get('output'):
                            service_details['details'] += "[?] Posible background de servicio "

            ip_services[ip_address].append(service_details)
    return ip_services



def print_subdomains_table(ip_subdomains, file=None):
    table = PrettyTable()
    table.field_names = ["IPs", "Subdominios"]
    ips = list(ip_subdomains.keys())
    for i, ip in enumerate(ips):
        subdomains = ip_subdomains[ip]
        # Añade la primera fila con la IP y el primer subdominio
        table.add_row([ip, subdomains[0]])
        # Añade el resto de subdominios para esta IP, sin repetir la IP
        for subdomain in subdomains[1:]:
            table.add_row(["", subdomain])
        # Si no es la última IP, añade una fila de separación
        if i < len(ips) - 1:
            table.add_row(['', ''])
            # Esto añade una línea en blanco entre grupos de IPs. 
            # Si quieres una línea divisoria visual (como +----+-----+), 
            # podría ser necesario ajustar manualmente cómo se genera esta salida, 
            # ya que PrettyTable no soporta directamente filas de separación personalizadas dentro de la tabla.
    
    if file:
        file.write(table.get_string())
    else:
        print(table)

def print_services_table(ip_services, file=None):
    table = PrettyTable()
    table.field_names = ["IPs", "Puertos", "Servicios", "Versiones", "Detalles"]
    for ip, services in ip_services.items():
        first = True
        for service in services:
            if first:
                row = [ip, service['port'], service['service'], service['version'], service['details'].strip()]
                first = False
            else:
                row = ["", service['port'], service['service'], service['version'], service['details'].strip()]
            table.add_row(row)
    if file:
        file.write(table.get_string())
    else:
        print(table)


def crear(results_directory):
    print_info("Creando reporte de fase de descubrimiento...")
    nmap_scan_file = os.path.join(results_directory, "vivos.nmap")
    xml_file = os.path.join(results_directory, "light.nmap.xml")
    output_file = os.path.join(results_directory, "discover_results.txt")
    
    ip_subdomains = parse_nmap_scan_results(nmap_scan_file)
    ip_services = parse_light_nmap_xml(xml_file)
    
    with open(output_file, "w") as file:
        print_subdomains_table(ip_subdomains, file)
        file.write("\n")  
        print_services_table(ip_services, file)

    print_success(f"Reporte de fase de descubrimiento creado correctamente en {output_file}")

if __name__ == "__main__":
    main()
