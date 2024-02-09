import os
from colorama import init, Fore
from utils.utils import *
from tools.vivos import comprobar_hosts_vivos
from tools.buscar_subdominios import buscar_subdominios
from tools.nmap import ejecutar_nmap
from tools.reporting import *
from tools.searchsploit import *
from tools.ffuf import *


# Inicializar Colorama
init(autoreset=True)

def main():
    # Imprimir el título del programa
    print_titulo()

    # Pedir al usuario que ingrese una URL o dirección IP para analizar
    user_input = ask_user("Por favor, ingrese una URL, una dirección IP o una IP con máscara de subred para analizar: ").strip()

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

    if not is_ip(user_input):
    # Verificar la existencia de subdominios.txt y preguntar si desea volver a buscar subdominios
        if comprobar_archivo_resultados(domain, "subdominios.txt"):
            opcion = ask_user("Los subdominios ya han sido obtenidos previamente. ¿Deseas volver a obtenerlos? (S/N): ").strip().lower()
            if opcion == "s":
                buscar_subdominios(domain)
        else:
            opcion = ask_user("¿Deseas buscar subdominios? (S/N): ").strip().lower()
            if opcion == "s":
                buscar_subdominios(domain)

    
    if comprobar_archivo_resultados(domain, "vivos.nmap"):
        opcion = ask_user("Los hosts vivos ya han sido comprobados previamente. ¿Deseas volver a comprobarlos? (S/N): ").strip().lower()
        if opcion == "s":
            comprobar_hosts_vivos(domain)
    else:
        opcion = ask_user("¿Deseas comprobar qué hosts están vivos? (S/N): ").strip().lower()
        if opcion == "s":
            comprobar_hosts_vivos(domain)

    if no_hay_hosts_vivos(ruta_en_resultados("vivos.nmap",domain)):
        print_error("Tu scope está muerto")

    else:

        if comprobar_archivo_resultados(domain, "nmap.xml"):
            opcion = ask_user("¿Ya se ha ejecutado una búsqueda de puertos y servicios anteriormente, deseas volver a hacerla? (S/N) ").strip().lower()
            if opcion == "s":
                ejecutar_nmap(domain)
        else:
            opcion_nmap = ask_user("¿Deseas realizar una búsqueda de puertos y servicios? (S/N): ").strip().lower()
            if opcion == "s":
                ejecutar_nmap(domain)

        
        if comprobar_archivo_resultados(domain, "exploits.json"):
            opcion = ask_user("¿Ya se ha ejecutado una búsqueda exploits anteriormente, deseas volver a hacerla? (S/N) ").strip().lower()
            if opcion == "s":
                searchsploit(domain)
        else:
            opcion = ask_user("¿Deseas realizar una búsqueda de exploits para los servicios encontrados? (S/N): ").strip().lower()
            if opcion == "s":
                searchsploit(domain)


        if comprobar_archivo_resultados(domain, "ffuf.json"):
            opcion = ask_user("¿Ya se ha ejecutado una búsqueda de subdirectorios anteriormente, deseas volver a hacerla? (S/N) ").strip().lower()
            if opcion == "s":
                ejecutar_ffuf(domain)
        else:
            opcion = ask_user("¿Deseas realizar una búsqueda de subdirectorios? (S/N): ").strip().lower()
            if opcion == "s":
                ejecutar_ffuf(domain)
    
            
    
if __name__ == "__main__":
    main()
