from colorama import init, Fore
import os

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
