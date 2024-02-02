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
    sudo nmap -Pn -sV -sC -iL ips.txt --open > nmap.txt
    echo "Análisis detallado con nmap completado y guardado en nmap.txt."
else
    echo "No se encontraron subdominios activos para el análisis detallado o el archivo nmap.txt ya estaba presente."
fi

#!/bin/bash

# Definición de archivos
ips_file="ips.txt"
subdominios_file="subdominios.txt"
vivos_file="vivos.txt"
nmap_file="nmap.txt"
notas_file="notas.txt"

# Limpiar el archivo de notas si ya existe
: > "$notas_file"

# Extraer y añadir IPs encontradas
echo "Ips encontradas = $(wc -l < "$ips_file" | awk '{print $1}')" >> "$notas_file"
while IFS= read -r ip; do
    echo -e "\t- $ip" >> "$notas_file"
done < "$ips_file"
echo "" >> "$notas_file"

# Añadir Subdominios UP
echo "Subdominios up = $(wc -l < "$vivos_file" | awk '{print $1}')" >> "$notas_file"
while IFS= read -r line; do
    echo -e "\t- $line" >> "$notas_file"
done < "$vivos_file"
echo "" >> "$notas_file"

# Añadir Subdominios DOWN
subdominios_down=$(comm -23 <(sort "$subdominios_file") <(sort "$vivos_file"))
echo "Subdominios down = $(echo "$subdominios_down" | wc -l | awk '{print $1}')" >> "$notas_file"
echo "$subdominios_down" | sed 's/^/\t- /' >> "$notas_file"
echo "" >> "$notas_file"

# # Añadir separador y título para detalles de IPs con algún puerto abierto
echo "------------------------------------------------------------------------------------------------------------------------------------------------" >> "$notas_file"
echo "Detalles Ips con algún puerto abierto:" >> "$notas_file"

# Extraer IPs y procesar detalles de puertos abiertos para cada IP
grep "Nmap scan report for" "$nmap_file" | grep -oP '\(\K[0-9\.]+(?=\))' | sort -u | while read -r ip; do
    echo -e "\n\t- $ip:" >> "$notas_file"
    # Ajustar awk para procesar correctamente los detalles de cada puerto abierto asociado a la IP
    awk -v ip="($ip)" '/Nmap scan report for/{current_ip=$NF} current_ip==ip && /^[0-9]+\/tcp/{
        printf "\t\t- %s %s %s", $1, $2, $3;
        for(i=4; i<=NF; i++) printf " %s", $i;
        printf "\n";
    }' "$nmap_file" >> "$notas_file"
done

echo "Resumen de análisis guardado en $notas_file"