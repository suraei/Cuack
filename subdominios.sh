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


