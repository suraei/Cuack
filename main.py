# main.py

from utils.utils import *
from tools.tools import *
from utils.reporting import *



def main():
    print_titulo()
    target = ask_user("Introduce el target (dominio, URL, IP o Subred): ")

    # Búsqueda de subdominios
    if not check_file_existence("subdominios.txt") or ask_user("Ya se ha realizado una búsqueda de subdominios previamente. ¿Quieres realizar la búsqueda de subdominios de nuevo? (S/N): ").lower() == 's':
        buscar_subdominios(target)

    # Comprobación de hosts vivos
    if not check_file_existence("host_vivos.xml") or ask_user("Ya se han comprobado los hosts vivos. ¿Quieres comprobarlo de nuevo? (S/N): ").lower() == 's':
        comprobar_hosts_vivos(target)

    # Ejecución de Nmap para análisis de puertos
    if not check_file_existence("nmap.xml") or ask_user("Ya se ha realizado una búsqueda de puertos y servicios previamente. ¿Quieres realizar la búsqueda de nuevo? (S/N): ").lower() == 's':
        if not check_file_existence("host_vivos.xml"):
            print_msg("No se encontró el archivo de hosts vivos necesario para realizar el análisis de Nmap.", "ERROR")
        else:
            ejecutar_nmap("host_vivos.xml")

    # Búsqueda de exploits
    if not check_file_existence("exploits.json") or ask_user("Ya se han buscado exploits previamente. ¿Quieres buscar de nuevo? (S/N): ").lower() == 's':
        if not check_file_existence("nmap.xml"):
            print_msg("No se encontró el archivo de Nmap necesario para buscar exploits.", "ERROR")
        else:
            buscar_exploits("nmap.xml")
    
    actualizar_reporte(target)
    

if __name__ == "__main__":
    main()
