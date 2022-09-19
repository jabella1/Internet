#!/bin/bash

#ESTE SCRIPT EJECUTARA EL COMANDO IPTABLES -F CADA CIERTO TIEMPO
#EN ESTE CASO LO PROGRAME PARA QUE SE EJECUTE CADA MINUTO
#EL COMANDO MENCIONADO, SIRVE EN POCAS PALABRAS PARA QUE LOS PUERTOS
#ABIERTOS SIRVAN EN LAS VPS DE ORACLE CLOUD


echo "Actualizando sistema..."

sudo apt update

echo "Instalando Cron..."
#Cron es un administrador de tareas de Linux que permite 
#ejecutar comandos en un momento determinado, por ejemplo, cada minuto, día, semana o mes.

sudo apt install cron

echo "Activando Cron..."

sudo systemctl enable cron

cd /usr/bin

echo "Descargando el script del repositorio de github..."
wget -O iptables_puertos "https://raw.githubusercontent.com/jabella1/Internet/main/iptables.sh"
chmod +x iptables_puertos

echo "Programando iptables cada minuto..."

* * * * * iptables_puertos >/dev/null 2>&1

echo "Terminado correctamente."

cd

rm -f Puertos_OracleCloud_VPS.sh


