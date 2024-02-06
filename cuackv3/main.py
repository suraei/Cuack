import os
from colorama import init, Fore
from utils.utils import *
from tools.vivos import comprobar_hosts_vivos
from tools.buscar_subdominios import buscar_subdominios
from tools.nmap import ejecutar_nmap
from tools.reporting import *


# Inicializar Colorama
init(autoreset=True)

def main():
    # Imprimir el título del programa
    print_titulo()

    # Pedir al usuario que ingrese una URL o dirección IP para analizar
    user_input = ask_user("Por favor, ingrese una URL o una dirección IP para analizar: ").strip()

    # Comprobar si la entrada es una dirección IP válida
    if is_ip(user_input):
        domain = user_input  
    else:
        # Si no es una dirección IP válida, comprobar si es una URL válida
        if is_valid_url(user_input):
            domain = obtener_dominio_desde_url(user_input)  # Obtener el dominio desde la URL
        else:
            # Si no es una URL válida ni una dirección IP válida, mostrar un mensaje de error
            print_error("La entrada no es una URL ni una dirección IP válida.")
            return

    # Verificar la existencia de subdominios.txt y preguntar si desea volver a buscar subdominios
    if comprobar_archivo_resultados(domain, "subdominios.txt"):
        opcion = ask_user("Los subdominios ya han sido obtenidos previamente. ¿Deseas volver a obtenerlos? (S/N): ").strip().lower()
        if opcion == "s":
            buscar_subdominios(domain)
    else:
        opcion = ask_user("¿Deseas buscar subdominios? (S/N): ").strip().lower()
        if opcion == "s":
            buscar_subdominios(domain)

    # Verificar la existencia de ips.txt y preguntar si desea volver a comprobar hosts vivos
    if comprobar_archivo_resultados(domain, "ips.txt"):
        opcion_vivos = ask_user("Los hosts vivos ya han sido comprobados previamente. ¿Deseas volver a comprobarlos? (S/N): ").strip().lower()
        if opcion_vivos == "s":
            comprobar_hosts_vivos(domain)

    else:
        opcion_vivos = ask_user("¿Deseas comprobar qué hosts están vivos? (S/N): ").strip().lower()
        if opcion_vivos == "s":
            comprobar_hosts_vivos(domain)

    if comprobar_archivo_resultados(domain, "vivos.nmap"):
        opcion_nmap = ask_user("¿Desea ejecutar Nmap para un análisis detallado de las IPs encontradas? (S/N): ").strip().lower()
        if opcion_nmap == "s":
            ejecutar_nmap(domain)
    else:
        print_warning("Primero debe realizar la comprobación de hosts vivos para generar el archivo ips.txt.")
        
if __name__ == "__main__":
    main()
