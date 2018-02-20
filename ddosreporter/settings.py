# -*- coding: utf-8 -*-

#Author: Mateus Ferreira Silva <mtsferreirasilva@gmail.com>

#Send emails to SYSADMs registered to each detected attack alert
#True to send emails, False not to send
SEND_EMAIL = False

#Email (gmail) and email password that will send the attack alert (server)
EMAIL_PASSWORD = ('sysadm@gmail.com', 'senha')

#SYSADMs mailing list
SYSADM = ('sysadm@gmail.com', )

#Demand limit for a single IP
REQUIREMENT_LIMIT_FOR_IP = 150
#LIMITE_REQUISICOES_POR_IP = 150

#Limit of distinct requests that the server can support
REQUIREMENT_LIMIT_TOTAL = 180
#LIMITE_REQUISICOES_TOTAL = 180

#Location of the apache log file (Default -> /var/log/apache2/access.log)
ARCHIVE_OF_LOG = '/var/log/apache2/access.log'
#ARQUIVO_DE_LOG = '/var/log/apache2/access.log'

#Block IPs so they no longer receive requests
#True to Block, False to not Block
BLOCK_ATTACKS = False
#BLOQUEAR_ATAQUES = False

#Iptables rule to block IPs
#(Default -> iptables -D INPUT -s <ip> -j DROP)
IPTABLES = 'iptables -I INPUT -s <ip> -j DROP'

#Time interval for log re-reading (time in seconds)
TIME_INTERVAL = 1
#INTERVALO_TEMPO = 1

# List blocked IPs:
# iptables -L INPUT -n --line-numbers
# Release IPs using list ID number:
# iptables -D INPUT <number>
