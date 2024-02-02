#!/bin/bash

# Solicitar al usuario que ingrese una URL
echo "Ingrese la URL del dominio (sin 'www.'): "
read domain

# Verificar si el usuario ingresó algo
if [[ -z "$domain" ]]; then
  echo "Debe ingresar una URL."
  exit 1
fi

theharvester_report="harvest_${domain//./_}.xml" # Asegúrate de que el nombre del archivo coincida con el esperado por theHarvester

# Comprobar si ya existe el archivo de theHarvester
if [ ! -f "$theharvester_report" ]; then
    # Iniciar la recolección de información con theHarvester en segundo plano, sin mostrar salida
    echo "Iniciando recolección de información con theHarvester para el dominio: $domain..."
    theHarvester -d $domain -b all -f $theharvester_report --save > /dev/null 2>&1 &
else
    echo "El archivo de theHarvester ya existe. Omitiendo esta etapa."
fi

# Continuar solo si subdominios.txt no existe
if [ ! -f subdominios.txt ]; then
    echo "Continuando con la búsqueda de subdominios para: $domain"

    tmpfile=$(mktemp)

    execute_tool() {
        local tool=$1
        local domain=$2
        local tmpfile=$3

        echo "Ejecutando ${tool} en busca de subdominios..."
        case $tool in
            amass)
                sudo amass enum -d "$domain" >> "$tmpfile" 2>/dev/null
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

    # Ejecutar cada herramienta en segundo plano y esperar a que todas terminen
    execute_tool amass "$domain" "$tmpfile" &
    execute_tool assetfinder "$domain" "$tmpfile" &
    execute_tool subfinder "$domain" "$tmpfile" &

    wait

    echo "Todas las herramientas han finalizado. Procesando resultados..."
    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$tmpfile" | sort -u > subdominios.txt
    rm "$tmpfile"
    echo "La búsqueda de subdominios ha finalizado. Los subdominios únicos se han guardado en subdominios.txt."
else
    echo "El archivo subdominios.txt ya existe. Omitiendo la búsqueda de subdominios."
fi

# Verificar subdominios activos solo si vivos.txt no existe
if [ ! -f vivos.txt ]; then
    echo "Verificando subdominios activos con nmap..."
    nmap_output=$(mktemp)
    nmap -sn -iL subdominios.txt 2>/dev/null > $nmap_output
    grep "Nmap scan report for" $nmap_output | awk '{if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $4; else print $5}'>vivos.txt
    rm $nmap_output
    echo "El escaneo de subdominios activos ha finalizado. Los subdominios activos se han guardado en vivos.txt."
else
    echo "El archivo vivos.txt ya existe. Omitiendo la verificación de subdominios activos."
fi

# Proceder con el escaneo detallado si vivos.txt tiene contenido
if [ -s vivos.txt ]; then
    echo "Iniciando análisis detallado con nmap sobre subdominios activos..."
    sudo nmap -Pn -sV -sC -iL vivos.txt --open > nmap.txt
    echo "Análisis detallado con nmap completado y guardado en nmap.txt."
else
    echo "No se encontraron subdominios activos para el análisis detallado o el archivo vivos.txt ya estaba presente."
fi

echo "Recolección de información con theHarvester está en proceso. Verifica ${theharvester_report} más tarde para los resultados."






if [ ! -f notas.txt ]; then
    echo "Creando notas.txt con un resumen de los resultados..."
    echo "Subdominios Totales: $(wc -l < subdominios.txt)" > notas.txt
    echo "Subdominios Vivos: $(wc -l < vivos.txt)" >> notas.txt
    echo "" >> notas.txt
    echo "Detalles de Subdominios Vivos:" >> notas.txt

    grep -Pzo "(?s)Nmap scan report for.*?(?=\n\n|\z)" nmap.txt | 
    while IFS= read -r -d '' report; do
        subdominio=$(echo "$report" | head -n 1 | awk '{print $NF}')
        echo "Subdominio: $subdominio" >> notas.txt
        echo "$report" | grep -P "^\d+\/tcp" | awk '{printf "    %s/%s %s %s\n", $1, $2, $3, $4}' >> notas.txt
    done
    echo "Resumen creado en notas.txt."
else
    echo "notas.txt ya existe. Omitiendo la creación de resumen."
fi
