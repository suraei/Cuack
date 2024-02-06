import subprocess
import os
from utils import print_info, print_success, print_error

def run_nmap(domain_file, nmap_output_file):
    """Ejecuta nmap para identificar subdominios vivos y guarda la salida en un archivo."""
    try:
        command = f"nmap -sn -iL {domain_file} 2>/dev/null -oN {nmap_output_file}"
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print_error(f"Error al ejecutar Nmap: {e}")

def process_nmap_output(nmap_output_file, live_subdomains_file, unique_ips_file):
    """Procesa la salida de Nmap y guarda subdominios vivos e IPs únicas."""
    unique_ips = set()
    live_subdomains = set()

    with open(nmap_output_file, "r") as file:
        lines = file.readlines()
        for line in lines:
            if "Nmap scan report for" in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    subdomain = parts[4]
                    ip = parts[-1][1:-1]  # Eliminar paréntesis
                    live_subdomains.add(subdomain)
                    unique_ips.add(ip)

    with open(live_subdomains_file, "w") as subdomains_file:
        for subdomain in live_subdomains:
            subdomains_file.write(subdomain + "\n")

    with open(unique_ips_file, "w") as ips_file:
        for ip in unique_ips:
            ips_file.write(ip + "\n")

    print_info(f"Identificación de subdominios vivos completada.Subdominios vivos guardados en {live_subdomains_file} e IPs únicas guardadas en {unique_ips_file}")

def identify_live_subdomains(domain, results_directory):
    """Identifica subdominios vivos utilizando Nmap."""
    domain_file = os.path.join(results_directory, "subdominios.txt")
    nmap_output_file = os.path.join(results_directory, "vivos.nmap")
    live_subdomains_file = os.path.join(results_directory, "vivos.txt")
    unique_ips_file = os.path.join(results_directory, "ips.txt")

    print_info("Identificando subdominios vivos con Nmap...")

    run_nmap(domain_file, nmap_output_file)
    process_nmap_output(nmap_output_file, live_subdomains_file, unique_ips_file)
