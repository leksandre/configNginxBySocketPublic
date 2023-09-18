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



def dns_lookup(host):
    
    import socket
    try:
        socket.getaddrinfo(host, 80)
    except socket.gaierror  as msg:
        print ("Type Error900: %s" % msg);
        return False
    return True


# print(dns_lookup('wowsucherror'))
# print(dns_lookup('google.com'))
# print(dns_lookup('marshmallow.re'))
# exit();
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

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

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
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
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

            m_time = os.path.getmtime(path+fileName)
            dt_m = datetime.datetime.fromtimestamp(m_time)
            print('Modified on:', dt_m)
            c_time = os.path.getctime(path+fileName)
            dt_c = datetime.datetime.fromtimestamp(c_time)
            print('Created on:', dt_c)
            later_time = datetime.datetime.now()
            difference = later_time - dt_m
            duration_in_s = difference.total_seconds()
            hours = divmod(duration_in_s, 3600)[0] 
            print('hours spent:', hours)
            if hours>2:
                if 3 < random.randint (0,int(hours)):
                    return False

            reloadNginx()  # рано
            os.chdir('/home/blablaservis3/docker_blablaservis/')
            res = generateConfignginx('.'.join(fparts))
            print(res)
            if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                changeFile2(path, fileName, fparts)
                newConfigWas = True
                reloadNginx()
            if(res.find('Certbot failed to authenticate some domains')>-1):
                return 'corrupted config';
        else:
            changeFile2(path, fileName, fparts)
            newConfigWas = True
            reloadNginx()
    else:
        checkSert1 = True
    if checkSert1:
        hostinfo = (get_certificate(('.'.join(fparts)),443))
        if hostinfo != 0:
            #print()
            print_basic_info(hostinfo)
            date_time_obj = hostinfo.cert.not_valid_after #datetime.datetime.strptime(hostinfo.cert.not_valid_after, '%y-%m-%d %H:%M:%S')
            # print ("The type of the date is now", (date_time_obj))
            now  = datetime.datetime.now() 
            duration = date_time_obj - now
            days  = duration.days
            print ("duration.days", (days))
            if days<3:
                os.chdir('/home/blablaservis3/docker_blablaservis/')
                res = generateConfignginx('.'.join(fparts))
                print(res)
                if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                    # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                    # changeFile2(path, fileName, fparts)
                    # newConfigWas = True
                    reloadNginx()
                if(res.find('Certbot failed to authenticate some domains')>-1):
                    return 'corrupted config';
        else:
            return 'corrupted config'

    fparts[0] = str(fparts[0])+'-admin'

    if find_phrases(path+fileName, 'server_name "domen3-admin.domen2.domen1";'):
        changeFileAdmin1(path, fileName, fparts)

    if find_phrases(path+fileName, 'ssl_certificate /etc/letsencrypt/live/domen3-admin.domen2.domen1/fullchain.pem;'):
        if not(os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):

            m_time = os.path.getmtime(path+fileName)
            dt_m = datetime.datetime.fromtimestamp(m_time)
            print('Modified on:', dt_m)
            c_time = os.path.getctime(path+fileName)
            dt_c = datetime.datetime.fromtimestamp(c_time)
            print('Created on:', dt_c)
            later_time = datetime.datetime.now()
            difference = later_time - dt_m
            duration_in_s = difference.total_seconds()
            hours = divmod(duration_in_s, 3600)[0] 
            print('hours spent:', hours)
            if hours>2:
                if 3 < random.randint (0,int(hours)):
                    return False

            reloadNginx()  # рано
            os.chdir('/home/blablaservis3/docker_blablaservis/')
            res = generateConfignginx('.'.join(fparts))
            print(res)
            if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                changeFileAdmin2(path, fileName, fparts)
                newConfigWas = True
                reloadNginx()
            if(res.find('Certbot failed to authenticate some domains')>-1):
                return 'corrupted config';
        else:
            changeFileAdmin2(path, fileName, fparts)
            newConfigWas = True
            reloadNginx()
    else:
        checkSert2 = True
    if checkSert2:
        hostinfo = (get_certificate(('.'.join(fparts)),443))
        if hostinfo != 0:
            print_basic_info(hostinfo)
            date_time_obj = hostinfo.cert.not_valid_after #datetime.datetime.strptime(hostinfo.cert.not_valid_after, '%y-%m-%d %H:%M:%S')
            # print ("The type of the date is now", (date_time_obj))
            now  = datetime.datetime.now() 
            duration = date_time_obj - now
            days  = duration.days
            print ("duration.days", (days))
            if days<3:
                os.chdir('/home/blablaservis3/docker_blablaservis/')
                res = generateConfignginx('.'.join(fparts))
                print(res)
                if res.find('Congratulations! Your certificate and chain have been saved at') > -1 or (os.path.isfile('/home/blablaservis3/docker_blablaservis/conf/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem')):
                    # if res.find('/etc/letsencrypt/live/'+('.'.join(fparts))+'/fullchain.pem') > -1:
                    # changeFileAdmin2(path, fileName, fparts)
                    # newConfigWas = True
                    reloadNginx()
                if(res.find('Certbot failed to authenticate some domains')>-1):
                    return 'corrupted config';

def checkUrl(fName):
    with open(fName) as f:
        datafile = f.readlines()
    for line in datafile:
        if "proxy_set_header Host" in line:
            arrLine = line.split(' ');
            #print(arrLine);
            if arrLine[-1]:
                url1 = ((arrLine[-1].strip().replace(';', '')));
                return (dns_lookup(url1))
    return None

def checkTheDir(directory):
  if os.path.isdir(directory):
    files = os.listdir(directory)
    arrayToRemove = []
    for conf1 in files:
        if conf1 != 'conf_template'  and conf1 != 'conf_template2custom' :
            if True:  # False
                result_process = processFile(directory, conf1)
                print(result_process,conf1);
                if result_process=='corrupted config':
                    res2 = checkUrl(directory+conf1);
                    print (res2)
                    if res2==False:
                        print ('!---------------------have to remove config to trash---------------------!  ')
                        arrayToRemove.append(directory+conf1);
            else:
                thread = threading.Thread(
                    target=processFile, args=(directory, conf1))
                thread.daemon = True
                thread.start()
    print('arrayToRemove',arrayToRemove);
    if len(arrayToRemove) < 10:
        for line in arrayToRemove:
            arrLine12 = line.split('/');
            if(arrLine12[-1]):
              print(line);
              os.replace(line, "/home/Aleksandr/corruptedConf/"+arrLine12[-1]);
  exit()


directory = '/home/blablaservis3/docker_blablaservis/conf/nginx/cnamedomain/'
print('------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
checkTheDir(directory)


#   filedata = None
#   with open(path+fileName, 'r') as file :
#     filedata = file.read()
#   filedata = filedata.replace('#    ssl_certificate /etc/letsencrypt/live/domen3.domen2.domen1/fullchain.pem;', '    ssl_certificate /etc/letsencrypt/live/domen3.domen2.domen1/fullchain.pem;')
#   filedata = filedata.replace('domen3.domen2.domen1',('.'.join(fparts1)) )
#   filedata = filedata.replace('domen2.domen1',('.'.join(fparts2)) ))
#   with open(path+fileName, 'w') as file:
#     file.write(filedata)


def countprocess(name):
    com = 'pgrep -f ' + str(name)

    p = subprocess.Popen([com], stdout=subprocess.PIPE, shell=True)
    res = p.communicate()[0]

    if isinstance(res, bytes):
        res = res.decode("utf-8")
    res = [str(x) for x in res.split('\n') if len(x) > 0]
    return len(res)


class Response1:
    def __init__(self, code1, text1):
        self.status_code = code1
        self.text = text1


def getip():

    try:
        r45 = requests.get('https://ident.me', proxies=proxies, timeout=1)
    except requests.exceptions.Timeout as e:
        print("\r SSL Error with : "+str(e))
        restartTor()
        return Response1("201", '')

    except requests.exceptions.RequestException as e:
        print("\r Error with  Credentials: "+str(e))
        restartTor()
        return Response1("201", '')
    except requests.ConnectionError:
        print("Can't connect to the site, sorry")
        return Response1("201", '')

    print(r45.text)

    return r45


def getCountryCode(ip=''):

    try:
        r45 = requests.get('https://freegeoip.app/json/' +
                           str(ip), proxies=proxies, timeout=1)
    except requests.exceptions.Timeout as e:
        print("\r SSL Error with : "+str(e))
        restartTor()
        return 0

    except requests.exceptions.RequestException as e:
        print("\r Error with  Credentials: "+str(e))
        restartTor()
        return 0
    except requests.ConnectionError:
        print("Can't connect to the site, sorry")
        return 0

    print(r45.text)
    d = json.JSONDecoder()
    rval = d.decode(r45.text)
    countryCode = rval['country_code']

    return countryCode


def find_all(a_str, sub):
    a_str = a_str.lower()
    sub = sub.lower()
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1:
            return
        yield start
        start += len(sub)


def create_connection(db_file):
    """ create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
    except Error as e:
        print(e)

    return conn


def makeGetRequestAddData(url, data, nproxy=False):

    if True:
        useTor = False
        r = Response1("0", '')

        try:
            randUa = user_agent_rotator.get_random_user_agent()

            if not data[9] is None:
                data9 = data[9]
            else:
                data9 = ''

            data2 = {"site": str(data[2])+str(data[1]), "resText": str(
                data9),   "resJson": (data9).split(",")}  # "resJsonArr": data[10],
            r = requests.post(url, headers={
                'origin': url,
                # 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'content-type': 'application/json',
                'user-agent': randUa
            }, timeout=120, allow_redirects=True, json=(data2), verify=False)
            print(r.text)
            # r.close()
        except requests.ConnectionError as e:
            print("[-] host die  ConnectionError: "+str(e))
        except requests.HTTPError as e:
            print("[-] host die  HTTPError: "+str(e))
        except requests.exceptions.ConnectTimeout as e:
            print("[-] host die  ConnectTimeout: "+str(e))
        except requests.exceptions.ReadTimeout as e:
            print("[-] host die  ReadTimeout: "+str(e))
        except requests.exceptions.Timeout as e:
            print("[-] host die  Timeout: "+str(e))
        except requests.exceptions.TooManyRedirects as e:
            print("[-] host die TooManyRedirects: "+str(e))
        except requests.exceptions.RequestException as e:
            print("[-]requests.exceptions.RequestException: "+str(e))
        except:
            print("[-] some excep: ")
            return None

        if int(r.status_code) != 200:
            return None

        return r

        if conpg:
            with conpg:
                with conpg.cursor() as curpg:
                    sql = " Update projects set fixed=True , statussite=%(statussite)s where id=%(id)s"
                    params = {"statussite": 'already ported',
                              "id": int(site[0])}
                    curpg.execute(sql, params)
                    conpg.commit()
                    print('fixed')
