#!/bin/bash

#ESTE SCRIPT EJECUTARA EL COMANDO IPTABLES -F CADA CIERTO TIEMPO
#EN ESTE CASO LO PROGRAME PARA QUE SE EJECUTE CADA 10 MINUTOS
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

rm -f iptables_puertos

echo "Descargando el script del repositorio de github..."
wget -O iptables_puertos "https://raw.githubusercontent.com/jabella1/Internet/main/iptables.sh"
chmod +x iptables_puertos

echo "Programando iptables cada minuto..."

cat << EOF >> /etc/crontab
*/2 * * * * root iptables_puertos
EOF
service cron restart

echo "Terminado correctamente."

cd

#comando para ejecucion
#rm -f Puertos_OracleCloud_VPS.sh && wget "https://raw.githubusercontent.com/jabella1/Internet/main/Puertos_OracleCloud_VPS.sh" && chmod +x Puertos_OracleCloud_VPS.sh && ./Puertos_OracleCloud_VPS.sh



