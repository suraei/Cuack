import xml.etree.ElementTree as ET
from prettytable import PrettyTable
import os

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
        try:
            ip_address = host.find("address[@addrtype='ipv4']").get("addr")
            ip_services[ip_address] = []
            for port in host.findall('.//port'):
                service = port.find('service')
                service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                service_product = service.get('product', '') if service is not None else ''
                service_version = service.get('version', '') if service is not None else ''
                portid = port.get('portid')
                protocol = port.get('protocol')
                ip_services[ip_address].append({
                    'port': f"{portid}/{protocol}",
                    'service': service_name,
                    'version': f"{service_product} {service_version}".strip()
                })
        except AttributeError:
            # Maneja casos donde el host no tiene una dirección IPv4 o la estructura es inesperada
            continue
    return ip_services

def print_subdomains_table(ip_subdomains, file=None):
    table = PrettyTable()
    table.field_names = ["IPs", "Subdominios Vivos"]
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
    table.field_names = ["IPs", "Puertos", "Servicios", "Versiones"]
    for ip, services in ip_services.items():
        first = True
        for service in services:
            if first:
                row = [ip, service['port'], service['service'], service['version']]
                first = False
            else:
                row = ["", service['port'], service['service'], service['version']]
            table.add_row(row)
    if file:
        file.write(table.get_string())
    else:
        print(table)

def crear(results_directory):
    nmap_scan_file = os.path.join(results_directory, "subdominios.nmap")
    xml_file = os.path.join(results_directory, "light.nmap.xml")
    output_file = os.path.join(results_directory, "discover_results.txt")
    
    ip_subdomains = parse_nmap_scan_results(nmap_scan_file)
    ip_services = parse_light_nmap_xml(xml_file)
    
    with open(output_file, "w") as file:
        print_subdomains_table(ip_subdomains, file)
        file.write("\n")  
        print_services_table(ip_services, file)

if __name__ == "__main__":
    main()
