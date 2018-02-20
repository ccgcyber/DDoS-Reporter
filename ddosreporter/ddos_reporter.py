#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author: Mateus Ferreira Silva <mtsferreirasilva@gmail.com>

import argparse
import file_writer
import os
import re
import send_email
import settings
import signal
import sys
import time

from version import get_version
from multiprocessing import Process


class Ddos_reporter():
    '''
    Monitor DoS and DDoS based on data from the access log of the web server Apache.\n
    It counts the number of requests and then it can block the IPs or only send alerts.
    '''

    def start_monitoring(self):
        '''
        Starts monitoring by capturing data from the log access
        '''
        print '\nMonitoring...'

        #Capturing file size to read from next block of bytes
        fileBytePos = os.path.getsize(settings.ARQUIVO_DE_LOG)

        #Object that will send emails in case of an attack
        email_sender = send_email.Send_Email()

        #Object that updates the ddosreporter log file
        fw = file_writer.File_writer()

        #Blocked Dictionary (Only in the current program execution, no
        #contains previous records)
        ipsBloqueados = {}

        #Last attacks suffered
        ultimoDoS = ''
        ultimoDDoS = ''

        #Regular expression
        regex = re.compile(r'(.+?) .+?\n')

        while True:
            with open(settings.ARQUIVO_DE_LOG, 'r') as _file:
                #Positioning to read from the previous byte
                _file.seek(fileBytePos)

                #Reading new log records, separating by '\n'
                data = _file.read()
                # data = data.split('\n')

                #Capturing only the IP(s) of each client
                access_list = re.findall(regex, data)

                #Checks house for overflow on request
                # possible per second
                if len(set(access_list)) > settings.LIMITE_REQUISICOES_TOTAL:
                    ips = []
                    for ip in set(access_list):
                        ips.append(ip)
                    ips = ', '.join(ips)
                    print '\033[1;31mATTENTION\033[0m - Limit overflow of {} requests per second (DDoS attack) \ nIPs:'.format(
                        settings.LIMITE_REQUISICOES_TOTAL), ips

                #Counting number of requests for each IP
                ipcounter = []
                for ip in set(access_list):
                    total = access_list.count(ip)
                    if total > settings.LIMITE_REQUISICOES_POR_IP:
                        if args.verbose:
                            print ip, '- Total:', total, '\033[0;31m(Attack detected)\033[0m'
                        ipcounter.append(ip)
                    else:
                        if args.verbose:
                            print ip, '- Total:', total

                #Defines type of attack
                if len(ipcounter) > 0:
                    #DDoS Attack---------------------------
                    if len(ipcounter) > 1:
                        ips = []
                        for ip in set(ipcounter):
                            ips.append(ip)
                        ips = ', '.join(ips)
                        if settings.BLOQUEAR_ATAQUES:
                            if ultimoDDoS != ips:
                                print '\033[1;31mAlert of DDoS Attack\033[0m - \033[1;32mIPs:', ips, '\033[0m'
                        else:
                            print '\033[1;31mAlert of DDoS Attack\033[0m - \033[1;32mIPs:', ips, '\033[0m'
                        ultimoDDoS = ips

                        #Blocking attack
                        if settings.BLOQUEAR_ATAQUES:
                            for ip in ipcounter:
                                if not (ip in ipsBloqueados):
                                    if os.system(re.sub(r'<ip>', ip, settings.IPTABLES)) == 0:
                                        ipsBloqueados[ip] = 'Blocking'
                                        print 'IP {} blocking'.format(ip)
                                        Process(target=fw.logAppend, args=('IP {} blocking\n'.format(ip), )).start()

                        #Sending Email
                        if settings.SEND_EMAIL:
                            print 'Sending email to SYSADM(s)...'
                            if len(settings.SYSADM) == 0:
                                print 'No registered SYSADM emails'
                            else:
                                for email in settings.SYSADM:
                                    Process(target=email_sender.send_email, args=(email, ipcounter, 1)).start()
                    else:
                        #DoS Attack------------------------
                        if settings.BLOQUEAR_ATAQUES:
                            if ultimoDoS != ipcounter[0]:
                                print '\033[1;31mAlert of DoS attack\033[0m - \033[1;32mIP:', ipcounter[0], '\033[0m'
                        else:
                            print '\033[1;31mAlert of DoS attack\033[0m - \033[1;32mIP:', ipcounter[0], '\033[0m'
                        ultimoDoS = ipcounter[0]

                        #Blocking attack
                        if settings.BLOQUEAR_ATAQUES:
                            if not (ipcounter[0] in ipsBloqueados):
                                if os.system(re.sub(r'<ip>', ipcounter[0], settings.IPTABLES)) == 0:
                                    ipsBloqueados[ipcounter[0]] = 'Blocking'
                                    print 'IP {} blocking'.format(ipcounter[0])
                                    Process(target=fw.logAppend, args=('IP {} blocking\n'.format(ipcounter[0]), )).start()

                        #Sending Email
                        if settings.SEND_EMAIL:
                            print 'Sending email(s) to SYSADM(s)...'
                            if len(settings.SYSADM) == 0:
                                print 'No registered SYSADM emails'
                            else:
                                for email in settings.SYSADM:
                                    Process(target=email_sender.send_email, args=(email, ipcounter[0], 0)).start()

                #Skip a line
                if data != '' and args.verbose:
                    print ''

                #Current file size
                fileBytePos = _file.tell()

                #Delay of x second (s) until next reading
                try:
                    time.sleep(settings.INTERVALO_TEMPO)
                except KeyboardInterrupt:
                    print '\nMonitoring completed\n'
                    exit()

    def print_settings(self):
        '''
        Prints the actual configuration of DDoSReporter
        '''
        print '\n\033[1;31m ATTENTION - EXECUTE AS A SUPERUSUARY (ROOT)\033[0;33m\n'
        print '\033[0;36m Version:\033[0;33m', get_version()
        print '\033[0;36m Log file:\033[0;33m', settings.ARQUIVO_DE_LOG
        sysadms = []
        for email in settings.SYSADM:
            sysadms.append(email)
        sysadms = ', '.join(sysadms)
        print '\033[0;36m SYSADMs:\033[0;33m', sysadms
        print '\033[0;36m Send alert emails:\033[0;33m', settings.SEND_EMAIL
        print '\033[0;36m Demand limit for a single IP:\033[0;33m', settings.LIMITE_REQUISICOES_POR_IP
        print '\033[0;36m Limit of different requests to the server:\033[0;33m', settings.LIMITE_REQUISICOES_TOTAL
        print '\033[0;36m Block attacks:\033[0;33m', settings.BLOQUEAR_ATAQUES
        if settings.BLOQUEAR_ATAQUES:
            print '\033[0;36m Rule iptables:\033[0;33m', settings.IPTABLES
        print '\033[0m'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action="store_true", help='Prints every access', default=False)
    args = parser.parse_args()

    monitor = Ddos_reporter()
    monitor.print_settings()
    monitor.start_monitoring()
