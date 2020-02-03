import re
import sys
import pymysql
import xml.etree.ElementTree as ET
import sniff

METHOD = re.compile(r"(POST|GET)")
HOST = re.compile(r"host\s?:\s?(?P<host> .*)", re.I)
CONTYPE = re.compile(r"content-type\s?:\s?(?P<contenttype> .*)", re.I)
USERNAME = re.compile(r"(userId|m_id|id)[^(&|=)]*=(?P<username>[^(&|=)]*)", re.I)
PASSWD = re.compile(r"(pass|userPw|pw)[^(&|=)]*=(?P<pass>[^(&|=|)]*)", re.I)

#pkt = b'POST /signIn.php/user HTTP/1.1\r\nHost: 192.168.0.40\r\nConnection: keep-alive\r\nContent-Length: 23\r\nCache-Control: max-age=0\r\nOrigin: http://192.168.0.40\r\nUpgrade-Insecure-Requests: 1\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nReferer: http://192.168.0.40/logIn.php\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: ko-KR,ko;q=0.9,en;q=0.8\r\n\r\nuserId=asdf&userPw=asdf'

def getPkt(pkt):
	pkt = pkt.decode()
	return pkt

def obfuscate(passwd):
	return passwd[0] + "*" * (len(passwd) - 2) + passwd[-1]

def parsePkt(inp):
	pkt = getPkt(inp)

	# host parse
	host = re.search(HOST, pkt)
	if not host:
		return None
	host = host.groups()[0]
	host = host.strip()

	# method call
	method = re.search(METHOD, pkt)
	if not method:
		return None
	method = method.groups()[0]

	# get | post 
	if method == 'GET':
		userid = re.search(USERNAME, pkt)
		if not userid:
			return None
		userid = userid.groups()[1]
		
		userpw = re.search(PASSWD, pkt)
		if not userpw:
			return None
		userpw = userpw.groups()[1]
	else:
		userid = re.search(USERNAME, pkt)
		print(userid)
		if not userid:
			return None
		userid = userid[-1][-1]

		
		userpw = re.findall(PASSWD, pkt)
		if not userpw:
			return None
		userpw = userpw[-1][-1]

	return (userid, obfuscate(userpw), host)

def countAdd(host):
	pass

def main():
	conn = pymysql.connect(host='localhost', user='jyp', password='wldbs11', db='wallofsheep')
	cur = conn.cursor()
	sql = 'INSERT into wos(id, pw, host, ip) values(%s, %s, %s, %s)'
	while(True):
		pkt, ip = sniff.sniff()
		rlt = parsePkt(pkt)
		uid, upw, host = rlt[0], rlt[1], rlt[2]
		if rlt is not None:
			try:
				print (uid, upw, host)
				cur.execute(sql, (uid, upw, host, ip))
				conn.commit()
				cur.execute('select * from wos')
				res = cur.fetchall()
				print(res)
			finally:
				conn.close()

	
if __name__ == "__main__":
	main()



'''
POST /index.php HTTP/1.1
Host: gilgil.net
Connection: keep-alive
Content-Length: 275
Origin: http://gilgil.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://gilgil.net/
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en;q=0.8
Cookie: sso=b2376caddca77ededbf960854d5826b3; PHPSESSID=078ec0f95a93d98f744d24eaa4604056
<?xml version="1.0" encoding="utf-8" ?>
<methodCall>
<params>
<user_id><![CDATA[test]]></user_id>
<password><![CDATA[1234]]></password>
<keep_signed><![CDATA[]]></keep_signed>
<module><![CDATA[member]]></module>
<act><![CDATA[procMemberLogin]]></act>
</params>
</methodCall>
'''
# 헤더에서 xml이면 xml 분석 모듈을 이용해서 