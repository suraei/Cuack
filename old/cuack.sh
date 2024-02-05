#!/bin/bash

# Solicitar al usuario que ingrese una URL
echo "Ingrese la URL del dominio (sin 'www.'): "
read domain

# Verificar si el usuario ingresó algo
if [[ -z "$domain" ]]; then
  echo "Debe ingresar una URL."
  exit 1
fi


# Continuar solo si subdominios.txt no existe
if [ ! -f subdominios.txt ]; then
    echo "Continuando con la búsqueda de subdominios para: $domain"
    tmpfile=$(mktemp)

    # Definir función para ejecutar herramientas de búsqueda de subdominios
    execute_tool() {
        local tool=$1
        local domain=$2
        local tmpfile=$3

        echo "Ejecutando ${tool} en busca de subdominios..."
        case $tool in
            amass)
                amass enum -d "$domain" >> "$tmpfile" 2>/dev/null
                ;;
            assetfinder)
                assetfinder --subs-only "$domain" >> "$tmpfile" 2>/dev/null
                ;;
            subfinder)
                subfinder -d "$domain" >> "$tmpfile" 2>/dev/null
                ;;
        esac
        echo "${tool} ha finalizado."
    }

    execute_tool amass "$domain" "$tmpfile" &
    execute_tool assetfinder "$domain" "$tmpfile" &
    execute_tool subfinder "$domain" "$tmpfile" &

    wait

    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$tmpfile" | sort -u > subdominios.txt
    rm "$tmpfile"
    echo "La búsqueda de subdominios ha finalizado. Los subdominios únicos se han guardado en subdominios.txt."
else
    echo "El archivo subdominios.txt ya existe. Omitiendo la búsqueda de subdominios."
fi

# Verificar subdominios activos solo si vivos.txt no existe
if [ ! -f ips.txt ]; then
    echo "Verificando subdominios activos con nmap..."
    nmap_output=$(mktemp)
    nmap -sn -iL subdominios.txt 2>/dev/null > $nmap_output
    grep "Nmap scan report for" $nmap_output | awk '{if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $4; else print $5}'>vivos.txt
    grep "Nmap scan report for" $nmap_output | grep -oP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' | sort -u > ips.txt
    rm $nmap_output
    echo "El escaneo de subdominios activos ha finalizado. Los subdominios activos se han guardado en vivos.txt."
    echo "La extracción de IPs activas ha finalizado. Las IPs activas se han guardado en ips.txt."
else
    echo "El archivo ips.txt ya existe. Omitiendo la verificación de subdominios activos."
fi


# Proceder con el escaneo detallado si nmap no existe 
if [ ! -f nmap.txt ]; then
    echo "Iniciando análisis detallado con nmap sobre ips activas con algún puerto abierto..."
    sudo nmap -Pn -sV -sC -iL ips.txt --open --script exploit,malware,version,vuln -script-args destination=/tmp/mirror > nmap.txt
    echo "Análisis detallado con nmap completado y guardado en nmap.txt."
else
    echo "No se encontraron subdominios activos para el análisis detallado o el archivo nmap.txt ya estaba presente."
fi



# Iniciar notas.txt con un encabezado y una breve introducción
echo "Resumen de la Búsqueda de Subdominios y Escaneo de Puertos" > notas.txt
echo "===========================================================" >> notas.txt
echo "" >> notas.txt

# Contar y listar subdominios activos
num_subdominios_activos=$(wc -l < vivos.txt)
echo "Número de subdominios activos: $num_subdominios_activos" >> notas.txt
echo "-----------------------------------------------------------" >> notas.txt
echo "Lista de subdominios activos:" >> notas.txt
cat vivos.txt >> notas.txt
echo "" >> notas.txt
echo "===========================================================" >> notas.txt

# Detalles de IPs y puertos abiertos
echo "Detalles de las IPs con algún puerto abierto:" >> notas.txt
echo "-----------------------------------------------------------" >> notas.txt
current_ip=""
current_service=""
waiting_for_background_check=false
vuln_detected=false
vuln_name=""
cve_id=""


while IFS= read -r line
do
  if [[ $line == Nmap\ scan\ report\ for* ]]; then
    if [[ $waiting_for_background_check == true ]]; then
      echo "         - [?] Posible background de otro servicio" >> notas.txt
      waiting_for_background_check=false
    fi
    current_ip=$(echo $line | grep -oP '\(\K[^\)]+')
    echo "" >> notas.txt
    echo "IP Analizada: $current_ip" >> notas.txt
    echo "-----------------------------" >> notas.txt
  elif [[ $line =~ ^[0-9]+/tcp.*open.* ]]; then
    if [[ $waiting_for_background_check == true ]]; then
      echo "         - [?] Posible background de otro servicio" >> notas.txt
      waiting_for_background_check=false
    fi
    current_port=$(echo $line | awk '{print $1}')
    current_service=$(echo $line | awk '{print $3}')
    version=$(echo $line | cut -d' ' -f4-)
    formatted_line=$(printf "      %-10s %-35s %s" "$current_port" "$current_service" "$version")
    echo "$formatted_line" >> notas.txt
    if [[ $current_service == "ssl/vrml-multi-use?" ]]; then
      waiting_for_background_check=true
    fi
  elif [[ $waiting_for_background_check == true && ($line =~ HTTPOptions.*200\ OK || $line =~ RTSPRequest.*200\ OK) ]]; then
    echo "         - [?] Posible background de otro servicio" >> notas.txt
    waiting_for_background_check=false
  elif [[ $line =~ ssl-cert && $line =~ TRAEFIK\ DEFAULT\ CERT ]]; then
    echo "         - [!] Redirecciona el tráfico" >> notas.txt
  elif [[ $line =~ http-title: && ! $line =~ Site\ doesn\'t\ have\ a\ title ]]; then
    title=$(echo $line | sed 's/.*http-title: //')
    echo "         - [*] $title" >> notas.txt
  elif [[ $line =~ Server: && $line != *Domain\ Name\ Server:* ]]; then
    server=$(echo $line | grep -oP '(?<=Server: ).*')
    echo "         - [*] Servidor: $server" >> notas.txt

  elif [[ $line =~ ^\|_http-fetch: && $line != *Please\ enter\ the\ complete\ path\ of\ the\ directory\ to\ save\ data\ in.* ]]; then
    fetch_data=$(echo $line | sed 's/|_http-fetch: //')
    echo "         - [i] Datos recogidos por http-fetch: $fetch_data" >> notas.txt
  fi
  # Detectar inicio de bloque de vulnerabilidad
  if [[ $line =~ VULNERABLE: ]]; then
    vuln_detected=true
    continue
  fi

  # Capturar el nombre de la vulnerabilidad inmediatamente después de "VULNERABLE:"
  if $vuln_detected && [[ -z $vuln_name ]]; then
    vuln_name=$line
    trim_vuln_name=$(echo $vuln_name | sed 's/|//g' | xargs) # Limpia y trim
    continue
  fi

  # Buscar y capturar el identificador CVE
  if $vuln_detected && [[ $line =~ CVE:CVE-[0-9]{4}-[0-9]+ ]]; then
    cve_id=$(echo $line | grep -oP 'CVE-[0-9]{4}-[0-9]+')
    echo "         - [!] $cve_id - $trim_vuln_name" >> notas.txt
    # Restablecer variables para la próxima vulnerabilidad
    vuln_detected=false
    vuln_name=""
    cve_id=""
  fi
done < nmap.txt

# Check for any pending background service annotations after the last line
if [[ $waiting_for_background_check == true ]]; then
  echo "         - [?] Posible background de otro servicio" >> notas.txt
fi

echo "" >> notas.txt
echo "===========================================================" >> notas.txt
echo "Fin del Resumen" >> notas.txt

echo "Resumen creado en notas.txt."
