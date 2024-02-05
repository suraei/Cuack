import os
import subprocess
from subdomain_finder import find_subdomains
from live_subdomains import identify_live_subdomains
from light_nmap import run_light_nmap
from utils import print_warning, print_info,ensure_directory,is_ip,write_ip_to_file
from discover_results import crear as discover_results_crear
from exploit import run_searchsploit
from dirb import run_dirb_on_ips,extract_ips_with_web_ports

def user_input(prompt):
    """Solicita entrada al usuario, mostrando el mensaje en amarillo."""
    print_warning(prompt)
    return input()

def main():
    domain = user_input("Por favor, introduce la URL o IP: ").strip()
    results_directory = ensure_directory(domain)
    subdomains_file = os.path.join(results_directory, "subdominios.txt")
    ips_file = os.path.join(results_directory, "ips.txt")
    nmap_file=os.path.join(results_directory, "light.nmap.xml")

    if not domain:
        print_warning("No se proporcionó una URL o IP válida. Terminando el programa.")
        return
    
    if is_ip(domain):
        print_info("Se ha detectado una dirección IP. Omitiendo la búsqueda de subdominios.Lanzando escaneo de Nmap...")
        write_ip_to_file(domain, ips_file)
    else:   
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

    # Llamada a run_dirb_on_ips desde dirb.py
    ips_with_web_ports = extract_ips_with_web_ports(nmap_file)
    user_choice = user_input("¿Deseas lanzar Dirb para encontrar subdirectorios en las páginas web? (s/n): ")
    if user_choice.lower() == 's':
        run_dirb_on_ips(ips_with_web_ports, results_directory)

    

if __name__ == "__main__":
    main()
