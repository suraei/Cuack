import subprocess
import os
from utils import *


def run_light_nmap(ips_file, results_directory):
    """Ejecuta nmap con el comando especificado."""
    print_info("Descubriendo servicios y puertos con nmap ...")
    output_file = os.path.join(results_directory, "light.nmap.xml")
    command = f"nmap -iL {ips_file} -sVC --open -oX {output_file}"

    subprocess.run(command, shell=True)
    print_warning(f"nmap finalizó correctamente.Los resultados se han guardado en {output_file}")
