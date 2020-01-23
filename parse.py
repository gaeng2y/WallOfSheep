import re
import sys
import sqlite3
# import sniff

con = sqlite3.connect('./test.db')
cur = con.cursor()

METHOD = re.compile(rb"(POST|GET)")
HOST = re.compile(rb"host\s?:\s?(?P<host> .*)", re.I)
USERNAME = re.compile(rb"(user|login|m_id|id)[^(&|=)]*=(?P<username>[^(&|=)]*)(&|$|\s|\[)", re.I)
PASSWD = re.compile(rb"(pass|user|pw)[^(&|=)]*=(?P<pass>[^(&|=|[)]*)(&|$|\s|\[)", re.I)


pkt = b'POST /signIn.php HTTP/1.1\r\nHost: 192.168.0.40\r\nConnection: keep-alive\r\nContent-Length: 23\r\nCache-Control: max-age=0\r\nOrigin: http://192.168.0.40\r\nUpgrade-Insecure-Requests: 1\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nReferer: http://192.168.0.40/logIn.php\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: ko-KR,ko;q=0.9,en;q=0.8\r\n\r\nuserId=asdf&userPw=asdf'

def connect():
    conn = sqlite3.connect(database='./test.db')
    conn.autocommit = True
    cur = conn.cursor()
    return cur

def obfuscate(passwd):
	return passwd[0] + "*" * (len(passwd) - 2) + passwd[-1]

def parsePkt(pkt):
	method = re.search(METHOD, pkt)
	if not method:
		return None
	method = method.groups()[0]
	method = method.decode('utf-8')
	print (method)

	host = re.search(HOST, pkt)
	if not host:
		return None
	host = host.groups()[0]
	host = host.decode('utf-8')
	host = host.strip()
	print(host)

	if method == "GET":
		userid = re.search(USERNAME, pkt)
		if not userid:
			return None
		userid = userid.groups()[1]
		userid = userid.decode('utf-8')
		print (userid)

		userpw = re.search(PASSWD, pkt)
		if not userpw:
			return None
		userpw = userpw.groups()[1]
		userpw = userpw.decode('utf-8')
		print (userpw)
	else:
		pass

parsePkt(pkt)
"""

def parsePkg(packet):
	ip = '127.0.0.1'
	pog = packet[0]


	cookieStart = pkg.find("Cookie:")
	cookieEnd = pkg.find("returnURL")
	cookie = pkg[cookieStart+8:cookieEnd-2]

	if pog == "G":
		username = str(re.search(USERNAME, pkg))
		if not username:
			return None
		idx = username.find("match=")
		lng = len(username)
		userid = username[idx+7:lng-3]
		cur.execute()

		passwd = str(re.search(PASSWD, pkg))
		if not passwd:
			return None
		idx = passwd.find("match=")
		lng = len(passwd)
		userpw = passwd[idx+7:lng-3]
		print(userpw)
	else:
		rURL = pkg.find("returnURL")
		pkg = pkg[rURL:]
		username = str(re.search(USERNAME, pkg))
		if not username:
			return None
		idx = username.find("match=")
		lng = len(username)
		userid = username[idx+7:lng-3]
		arrUserId = userid.split('=')
		userID = arrUserId[1]

		passwd = str(re.search(PASSWD, pkg))
		if not passwd:
			return None
		idx = passwd.find("match=")
		lng = len(passwd)
		userpw = passwd[idx+7:lng-3]
		arrUserPw = userpw.split('=')
		userPW = arrUserPw[1]

	#cur.execute('INSERT INTO wos (id, pw, ip, host, cookie) VALUES(?, ?, ?, ?, ?);', (userID, userPW, ip, hostName, cookie))
	#con.commit()

parsePkg(pkg)
"""