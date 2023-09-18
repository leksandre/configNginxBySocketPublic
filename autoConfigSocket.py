import pprint
import time
import sys
import os
import re
import threading
import datetime
import random
import json
import string
import subprocess
import urllib.parse
from datetime import timezone
import fileinput
from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
from socket import socket
from collections import namedtuple
import socket

global newConfigWas
newConfigWas = False


name = sys.argv[0].split('/')[-1]
com = 'pgrep -f ' + name
# print(com)
totalQueries = 0

p = subprocess.Popen([com], stdout=subprocess.PIPE, shell=True)
res = p.communicate()[0]

if isinstance(res, bytes):
    res = res.decode("utf-8")
res = [str(x) for x in res.split('\n') if len(x) > 0]
# print(len(res))
if len(res) > 2:
    print('Already running!')
    print('Exit!')
    exit()
    exit()
    exit()


HostInfo = namedtuple(
    field_names='cert hostname peername', typename='HostInfo')


def find_phrases(filename, phrases):
    with open(filename) as file:
        str1 = file.read()
        if len(str1) == 0:
            return False
        text = ' '.join(str1.split())
    start = text.find(phrases)
    # print(text)
    print('found phrases ', phrases, 'in', start)
    if start == -1:
        return False
    else:
        return True


def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None


def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def reloadNginx():
    com = 'docker container exec mbst_nginx nginx -s reload'
    p = subprocess.Popen([com], stdout=subprocess.PIPE, shell=True,
                         stderr=subprocess.PIPE)
    p.wait()
    # result11 = p.stdout.readlines()
    # print(result11)
    res = p.communicate()[0]
    if isinstance(res, bytes):
        res = res.decode("utf-8")
    res = [str(x) for x in res.split('\n') if len(x) > 0]
    print('res reload nginx: ',  res)


def generateConfignginx(site1):
    # print(site1) #
    com = './docker-gets-ssl_v2.sh '+str(site1)
    p = subprocess.Popen([com], stdout=subprocess.PIPE, shell=True,
                         stderr=subprocess.PIPE)
    p.wait()
    # result11 = p.stdout.readlines()
    # print(result11)
    output = p.stdout.read()
    print('stdout: ', len(output))
    err1 = p.stderr.read()
    print('stderr: ', len(err1))
    res = p.communicate()[0]
    if isinstance(res, bytes):
        res = res.decode("utf-8")
    res = [str(x) for x in res.split('\n') if len(x) > 0]
    print('res generate confignginx: ', res)

    if len(res) == 0:
        if isinstance(output, bytes):
         output1 = output.decode("utf-8")
         res = [str(x) for x in output1.split('\n') if len(x) > 0]
        #  print('res stdout', res)
         if len(res) == 0:
          if isinstance(output, bytes):
           err12 = err1.decode("utf-8")
           res = [str(x) for x in err12.split('\n') if len(x) > 0]
        #  print('res stderr', res)

    # p =  subprocess.Popen(['sh', './docker-gets-ssl.sh', str(site1)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # p.wait()
    # output, err = p.communicate(b"input data that is passed to subprocess' stdin")
    # rc = p.returncode
    # print(rc, output, err)

    #subprocess.call([sys.executable,"/root/test2.py","1"])

    # p = os.system('./docker-gets-ssl.sh '+str(site1))
    # print(p)
    return ' '.join(res)


def changedomen0(path, fileName, fparts1):
  fparts2 = fparts1.copy()
  fparts2.pop(0)
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('https://domen2.domen1',
                           'https://'+('.'.join(fparts2))), end='')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('Host domen2.domen1',
                           'Host '+('.'.join(fparts2))), end='')


def changeFile1(path, fileName, fparts1):
  print('changeFile1')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('server_name "domen3.domen2.domen1";',
                           'server_name "'+('.'.join(fparts1))+'";'), end='')


def changeFileAdmin1(path, fileName, fparts1):
  print('changeFileAdmin1')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('server_name "domen3-admin.domen2.domen1";',
                           'server_name "'+('.'.join(fparts1))+'";'), end='')


def changeFile2(path, fileName, fparts1):
  print('changeFile2')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('#    ssl_certificate /etc/letsencrypt/live/domen3.domen2.domen1/fullchain.pem;',
                           '    ssl_certificate /etc/letsencrypt/live/domen3.domen2.domen1/fullchain.pem;'), end='')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('#    ssl_certificate_key /etc/letsencrypt/live/domen3.domen2.domen1/privkey.pem;',
                           '    ssl_certificate_key /etc/letsencrypt/live/domen3.domen2.domen1/privkey.pem;'), end='')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('domen3.domen2.domen1', ('.'.join(fparts1))), end='')


def changeFileAdmin2(path, fileName, fparts1):
  print('changeFileAdmin2')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('#    ssl_certificate /etc/letsencrypt/live/domen3-admin.domen2.domen1/fullchain.pem;',
                           '    ssl_certificate /etc/letsencrypt/live/domen3-admin.domen2.domen1/fullchain.pem;'), end='')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('#    ssl_certificate_key /etc/letsencrypt/live/domen3-admin.domen2.domen1/privkey.pem;',
                           '    ssl_certificate_key /etc/letsencrypt/live/domen3-admin.domen2.domen1/privkey.pem;'), end='')
  with fileinput.FileInput(path+fileName, inplace=True) as file:
    for line in file:
        print(line.replace('domen3-admin.domen2.domen1', ('.'.join(fparts1))), end='')


def print_basic_info(hostinfo):
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter} '''.format(
        hostname=hostinfo.hostname,
        peername=hostinfo.peername,
        commonname=get_common_name(hostinfo.cert),
        SAN=get_alt_names(hostinfo.cert),
        issuer=get_issuer(hostinfo.cert),
        notbefore=hostinfo.cert.not_valid_before,
        notafter=hostinfo.cert.not_valid_after
    )
    print(s)


def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()
    try:
        sock.connect((hostname, port))
    except TypeError as msg:
        print ("Type Error2: %s" % msg)
        return 0
    except Exception as msg:
        print ("Type Error3: %s" % msg)
        return 0
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    try:
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
    except Exception as msg:
        print ("Type Error3: %s" % msg)
        return 0
    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)


def processFile(path, fileName):
    fileName2 = fileName[:-5]
    fparts = fileName2.split('_')
    fparts.pop(0)
    fparts.pop(0)
    print(' ')
    print(' ')
    print(' ')
    print(fileName, '-----')

    if find_phrases(path+fileName, 'https://domen2.domen1'):
        changedomen0(path, fileName, fparts)

    checkSert1 = False
    checkSert2 = False

    if find_phrases(path+fileName, 'server_name "domen3.domen2.domen1";'):
        changeFile1(path, fileName, fparts)

    if find_phrases(path+fileName, 'ssl_certificate /etc/letsencrypt/live/domen3.domen2.domen1/fullchain.pem;'):
        if not(os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
            reloadNginx()  # рано
            os.chdir('/home/blablaservis3/docker_blablaservis/')
            res = generateConfignginx('.'.join(fparts))
            print(res)
            if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                changeFile2(path, fileName, fparts)
                newConfigWas = True
                reloadNginx()
        else:
            changeFile2(path, fileName, fparts)
            newConfigWas = True
            reloadNginx()
    else:
        checkSert1 = True
    if checkSert1:
        hostinfo = (get_certificate(('.'.join(fparts)), 443))
        #print()
        if hostinfo != 0:
            print_basic_info(hostinfo)
            # datetime.datetime.strptime(hostinfo.cert.not_valid_after, '%y-%m-%d %H:%M:%S')
            date_time_obj = hostinfo.cert.not_valid_after
            # print ("The type of the date is now", (date_time_obj))
            now = datetime.datetime.now()
            duration = date_time_obj - now
            days = duration.days
            print("duration.days", (days))
            if days < 3:
                os.chdir('/home/blablaservis3/docker_blablaservis/')
                res = generateConfignginx('.'.join(fparts))
                print(res)
                if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                    # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                    # changeFile2(path, fileName, fparts)
                    # newConfigWas = True
                    reloadNginx()

    fparts[0] = str(fparts[0])+'-admin'

    if find_phrases(path+fileName, 'server_name "domen3-admin.domen2.domen1";'):
        changeFileAdmin1(path, fileName, fparts)

    if find_phrases(path+fileName, 'ssl_certificate /etc/letsencrypt/live/domen3-admin.domen2.domen1/fullchain.pem;'):
        if not(os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
            reloadNginx()  # рано
            os.chdir('/home/blablaservis3/docker_blablaservis/')
            res = generateConfignginx('.'.join(fparts))
            print(res)
            if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                changeFileAdmin2(path, fileName, fparts)
                newConfigWas = True
                reloadNginx()
        else:
            changeFileAdmin2(path, fileName, fparts)
            newConfigWas = True
            reloadNginx()
    else:
        checkSert2 = True
    if checkSert2:
        hostinfo = (get_certificate(('.'.join(fparts)), 443))
        if hostinfo != 0:
            print_basic_info(hostinfo)
            # datetime.datetime.strptime(hostinfo.cert.not_valid_after, '%y-%m-%d %H:%M:%S')
            date_time_obj = hostinfo.cert.not_valid_after
            # print ("The type of the date is now", (date_time_obj))
            now = datetime.datetime.now()
            duration = date_time_obj - now
            days = duration.days
            print("duration.days", (days))
            if days < 3:
                os.chdir('/home/blablaservis3/docker_blablaservis/')
                res = generateConfignginx('.'.join(fparts))
                print(res)
                if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                    # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                    # changeFileAdmin2(path, fileName, fparts)
                    # newConfigWas = True
                    reloadNginx()


def checkTheDir(directory, sitename=''):
  print('sitename start!!', sitename)

  if os.path.isdir(directory):
    files = os.listdir(directory)
    for conf1 in files:
        # print(sitename, 'file try', conf1)
        if conf1 != 'conf_template' and conf1 != 'conf_template2custom' and (sitename == '' or conf1.find(sitename) > -1):
            print(sitename, 'file found', conf1)
            if True:  # False
                processFile(directory, conf1)
            else:
                thread = threading.Thread(
                    target=processFile, args=(directory, conf1))
                thread.daemon = True
                thread.start()


def main():
    host = ""
    port = 9090
    backlog = 5
    size = 1024
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client_socket.connect(host,port)
    # host, port = client_socket.getpeername()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(backlog)

    while True:
        client, address = sock.accept()
        print("Client connected.")
        ip, port = sock.getsockname()
        print(ip, port)
        while True and client:
            data = client.recv(size).rstrip()
            cbytes=sys.getsizeof(data)
            if cbytes<10:
                client.send(data)
                client.close()
                break
            print("Received data: %s" % data)
            print("Count bytes: %s" % cbytes)
            if isinstance(data, bytes):
                # print(data, 'data')
                # lines=res.splitlines()
                lines=data.split(b'\r\n')
                print(lines)
                if len(lines)>0:
                  res = lines[-1].decode('UTF-8')
                #   print(res,'res')
                  if isinstance(res, str):
                    data = res.replace('.', '_')
            # print("Executing command: %s" % data)
            # print("Start command: %s" % data)
            print(data, 'data')
            print(type(data))
            if not data:
                print("skip")
                continue
            if data == "disconnect":
                print("Client disconnected.")
                client.send(data)
                client.close()
                break
            else:
                if data == "exit":
                    print("Client asked server to quit")
                    client.send(data)
                    client.close()
                    return
                else:
                    print('------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
                    if data == "config":
                        directory = '/home/blablaservis3/docker_blablaservis/conf/nginx/cnamedomain/'
                        checkTheDir(directory)
                        return
                    else:
                        if data.find('process_config_')==0:
                            data = data.replace('process_config_', '')
                            directory = '/home/blablaservis3/docker_blablaservis/conf/nginx/cnamedomain/'
                            checkTheDir(directory, data)
                    print('------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
            client.send(b'Success')
            client.close()
            break
            print("End command: %s" % data)
            # try:
            #     exec(data)#danger, realy danger
            # except Exception as err:
            #     print("Error occured while executing command: %s" % (
            #             data), str(err))


main()
