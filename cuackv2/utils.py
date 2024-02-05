from colorama import init, Fore
import os
import ipaddress

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


