#tools.py
from utils.utils import *

def buscar_subdominios(target):
    commands = [
        ["amass", "enum", "-d", target],
        ["assetfinder", "--subs-only", target],
        ["subfinder", "-d", target]
    ]
    output_file = "subdominios.txt"
    execute_tools_in_parallel(commands, output_file)

def comprobar_hosts_vivos(target):
    if (RESULTS_DIR / "subdominios.txt").exists():
        command = ["nmap", "-sn","-vv", "-iL", str(RESULTS_DIR / "subdominios.txt"), "-T4", "-oX", str(RESULTS_DIR / "host_vivos.xml")]
    else:
        command = ["nmap", "-sn", target, "-T4", "-oX", str(RESULTS_DIR / "host_vivos.xml")]
    execute_tool(command)

def ejecutar_nmap(hosts_vivos):
    temp_ips_file_path = extract_unique_ips(hosts_vivos)
    
    if temp_ips_file_path and temp_ips_file_path.is_file():
        command = [
            "nmap", "-sVC", "-T4", "--open", "-iL",
            str(temp_ips_file_path),  
            "-oX", str(RESULTS_DIR / 'nmap.xml')
        ]
        
        execute_tool(command)
        print_msg("Análisis de Nmap sobre hosts vivos completado. Resultados guardados en nmap.xml", "INFO")
        temp_ips_file_path.unlink()
    else:
        print_msg("No se encontraron hosts vivos para el análisis de Nmap o hubo un error al extraerlos.", "WARNING")

def buscar_exploits(xml_file):
    nmap_info = parse_nmap_xml(xml_file)

    unique_products = get_unique_products_with_ips_ports(nmap_info)

    output_file = "exploits.json"
    for product, affected_hosts in unique_products.items():
        command = ["searchsploit", product, "--exclude=Denial of Service", "--json"]
        execute_tool(command, output_file)

    for product, affected_hosts in unique_products.items():
        add_affected_hosts_to_json("exploits.json", "RESULTS_EXPLOIT","Title",product, affected_hosts)
