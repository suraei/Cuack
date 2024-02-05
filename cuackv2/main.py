import os
import subprocess
from subdomain_finder import find_subdomains
from live_subdomains import identify_live_subdomains
from light_nmap import run_light_nmap
from utils import print_warning, print_info,ensure_directory
from discover_results import crear as discover_results_crear
from exploit import run_searchsploit


def user_input(prompt):
    """Solicita entrada al usuario, mostrando el mensaje en amarillo."""
    print_warning(prompt)
    return input()

def main():
    domain = user_input("Por favor, introduce la URL: ").strip()
    if not domain:
        print_warning("No se proporcionó una URL válida. Terminando el programa.")
        return

    results_directory = ensure_directory(domain)
    subdomains_file = os.path.join(results_directory, "subdominios.txt")
    ips_file = os.path.join(results_directory, "ips.txt")
    nmap_file=os.path.join(results_directory, "light.nmap.xml")

    if os.path.exists(subdomains_file):
        user_choice = user_input("El archivo 'subdominios.txt' ya existe. ¿Quieres volver a lanzar el buscador de subdominios? (s/n): ").lower()
        if user_choice == 's':
            find_subdomains(domain, results_directory)
    else:
        find_subdomains(domain, results_directory)

    if os.path.exists(ips_file):
        user_choice = user_input("El archivo 'ips.txt' ya existe. ¿Quieres volver a lanzar el identificador de subdominios vivos e IPs? (s/n): ").lower()
        if user_choice == 's':
            identify_live_subdomains(subdomains_file, results_directory)
    else:
        identify_live_subdomains(subdomains_file, results_directory)
    
    if os.path.exists(nmap_file):
        user_choice = user_input("El archivo 'light.nmap.xml' ya existe. ¿Quieres volver a lanzar el escaneo de Nmap? (s/n): ").lower()
        if user_choice == 's':
            run_light_nmap(ips_file, results_directory)
    else:
        run_light_nmap(ips_file, results_directory)
    
    discover_results_crear(results_directory)
    run_searchsploit(nmap_file, results_directory, domain)

if __name__ == "__main__":
    main()
