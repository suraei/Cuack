from colorama import init, Fore
import os
import ipaddress
import xml.etree.ElementTree as ET

# Inicializa Colorama para habilitar la impresión en colores en la terminal.
init(autoreset=True)

def print_info(message):
    """Imprime un mensaje informativo en azul."""
    print(Fore.BLUE + "[*] " + message)

def print_success(message):
    """Imprime un mensaje de éxito en verde."""
    print(Fore.GREEN + "[!] " + message)

def print_error(message):
    """Imprime un mensaje de error en rojo."""
    print(Fore.RED + "[X] " + message)

def print_warning(message):
    """Imprime un mensaje de advertencia en amarillo."""
    print(Fore.YELLOW + "[*] " + message)

def ensure_directory(domain):
    """Asegura la creación de un directorio para los resultados, basado en el dominio."""
    directory = domain if not domain.startswith("www.") else domain[4:]
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
    return directory

def is_ip(address):
    """Determina si la cadena dada es una dirección IP válida."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def write_ip_to_file(ip, file_path):
    """Escribe la dirección IP en el archivo especificado."""
    with open(file_path, 'w') as file:
        file.write(ip + '\n')
    print_info(f"La dirección IP {ip} ha sido guardada en {file_path}.")

def print_colored_animals():
    """Imprime un arte ASCII de un conejito y un pato con colores."""
    # Define los colores utilizando códigos de escape ANSI
    class Colors:
        YELLOW = '\033[93m'
        WHITE = '\033[97m'
        RESET = '\033[0m'

    # Dibuja el conejito y el pato con colores
    arte = f"""
{Colors.WHITE}   (\\(\\    {Colors.YELLOW}  >(.)__ <( Quack! )
{Colors.WHITE}   (-.-)    {Colors.YELLOW}    (___/  
{Colors.WHITE}  o_(")("){Colors.RESET}
    """
    print(arte)

def extract_ips_with_web_ports(nmap_file):
    """
    Extrae las IPs que tienen puertos web abiertos de un archivo nmap en formato XML.
    
    Args:
        nmap_file (str): Ruta al archivo nmap XML.
    
    Returns:
        list: Lista de IPs con puertos web abiertos.
    """
    web_ports = {'80', '443', '8080', '8000'}  # Define los puertos web comunes
    ips_with_web_ports = []

    tree = ET.parse(nmap_file)
    root = tree.getroot()

    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':  # Solo considera hosts activos
            ip_address = host.find('address').get('addr')
            ports = host.find('ports').findall('port')
            for port in ports:
                if port.get('protocol') == 'tcp' and port.get('portid') in web_ports and port.find('state').get('state') == 'open':
                    ips_with_web_ports.append(ip_address)
                    break  # Si encuentra un puerto web abierto, añade la IP y continúa con el siguiente host

    return ips_with_web_ports


