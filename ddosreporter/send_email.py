# -*- coding: cp860 -*-

#Author: Mateus Ferreira Silva <mtsferreirasilva@gmail.com>

import getpass
import re
import settings
import smtplib
import sys

from email.Utils import formatdate
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText


class Send_Email():
    '''
    Class to send email to Gmail domain
    '''

    def email_validator(self, email):
        '''
        Validates an email using regular expression

        Args:
            email (str) - Email

        Returns 1 for valid email and 0 for invalid
        '''

        #Check email integrity
        if re.match('^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$', email) is not None:
            return 1
        return 0

    def send_email(self, email, ips, atk=0):
        '''
        Send an email alert informing DDoS / Dos

        Args:
            email (str) - SYSADM email\n
            ips (str) - List of the ips detected\n
            atk (int) - Type of attack detected (0->DoS, 1->DDoS)
        '''

        #Checks SYSADM email
        if not self.email_validator(email):
            print email, '- Invalid Email'
        #Checks mail from server and if a SYSADM exists
        elif len(settings.EMAIL_PASSWORD) == 2 and len(settings.SYSADM) > 0:
            if not self.email_validator(settings.EMAIL_PASSWORD[0]):
                print email, '- Email inválido'
            else:
                #Email Header
                msg = MIMEMultipart()
                msg['From'] = settings.EMAIL_PASSWORD[0]
                msg['To'] = email
                msg['Date'] = formatdate(localtime=True)

                #Email Message
                if atk == 0:
                    msg['Subject'] = 'DoS Alert'
                    message = []
                    message.append(
                        'We have identified that your web address is undergoing an IP DoS attack {}.'.format(ips))
                    # BLOCK_ATTACKS
                    if settings.BLOCK_ATTACKS:
                        message.append(
                            '\n\nIP was blocked following the iptables rule \"{}\".'.format(settings.IPTABLES))
                    message.append(
                        '\n\n\tThis message was generated automatically by the system, do not reply to this email.')
                    message = ''.join(message)
                    msg.attach(MIMEText(message))
                elif atk == 1:
                    msg['Subject'] = 'DDoS Alert'
                    message = []
                    message.append(
                        'We have identified that your web address is suffering a DDoS attack from IPs:\n')
                    for ip in ips:
                        message.append('\n>> {}'.format(ip))
                    if settings.BLOCK_ATTACKS:
                        message.append(
                            '\n\nOs IPs were blocked following the iptables rule \"{}\".'.format(settings.IPTABLES))
                    message.append(
                        '\n\n\tThis message was generated automatically by the system, do not reply to this email.')
                    message = ''.join(message)
                    msg.attach(MIMEText(message))

                #Sending emails
                try:
                    server = smtplib.SMTP('smtp.gmail.com', 587)
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(settings.EMAIL_PASSWORD[0], settings.EMAIL_PASSWORD[1])
                    server.sendmail(settings.EMAIL_PASSWORD[0], email, msg.as_string())
                    if atk == 0:
                        ipEnviar = ips
                    else:
                        ipEnviar = []
                        for ip in ips:
                            ipEnviar.append(ip)
                        ipEnviar = ', '.join(ipEnviar)

                    print 'Email sent to {} about IP attack: {}'.format(email, ipEnviar)
                except SMTPServerDisconnected:
                    sys.stderr.write('ERROR: Failed to send email. Server disconnected.')
                except SMTPRecipientsRefused:
                    sys.stderr.write('ERROR: Failed to send email. Refused recipients.')
                except SMTPResponseException:
                    sys.stderr.write('ERROR: Failed to send email. Failed to receive response.')
                except SMTPAuthenticationError:
                    sys.stderr.write('ERROR: Failed to send email. Email authentication failed.')
                except SMTPConnectError:
                    sys.stderr.write('ERROR: Failed to send email. Failed to connect to server.')
                except SMTPDataError:
                    sys.stderr.write('ERROR: Failed to send email. Server refused the sent message.')
                except SMTPHeloError:
                    sys.stderr.write('ERROR: Failed to send email. Server refused HELO message')
                except SMTPSenderRefused:
                    sys.stderr.write('ERROR: Failed to send email. Source address failure')
                except SMTPException:
                    sys.stderr.write('ERROR: Failed to send email.')
                finally:
                    server.close()
        elif len(settings.EMAIL_PASSWORD) == 0:
            sys.stderr.write('ERROR: Email to send the alerts has not yet been configured. Check the settings.py file')
        else:
            sys.stderr.write('ERROR: Failed email variables reported. Check the settings.py file.')
