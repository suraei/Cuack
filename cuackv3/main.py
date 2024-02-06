import os
from colorama import init, Fore
from utils.utils import *
from tools.vivos import *  
from tools.buscar_subdominios import *

# Inicializar Colorama
init(autoreset=True)

def main():
    # Imprimir el título del programa
    print_titulo()

    # Pedir al usuario que ingrese una URL o dirección IP para analizar
    user_input = input("Por favor, ingrese una URL o una dirección IP para analizar: ").strip()

    # Comprobar si la entrada es una dirección IP válida
    if is_ip(user_input):
        print_info("ES UNA IP VALIDA")
        domain = user_input  
    else:
        # Si no es una dirección IP válida, comprobar si es una URL válida
        if is_valid_url(user_input):
            domain = obtener_dominio_desde_url(user_input)  # Obtener el dominio desde la URL
            print_info("ES UNA URL VALIDA")
            opcion = input("¿Deseas buscar subdominios? (S/N): ").strip().lower()
            if opcion == "s":
                buscar_subdominios(domain)
        else:
            # Si no es una URL válida ni una dirección IP válida, mostrar un mensaje de error
            print_error("La entrada no es una URL ni una dirección IP válida.")
            return

    # Pregunta si desea comprobar hosts vivos
    opcion_vivos = input("¿Deseas comprobar qué hosts están vivos? (S/N): ").strip().lower()
    if opcion_vivos == "s":
        comprobar_hosts_vivos(domain)
        
if __name__ == "__main__":
    main()
