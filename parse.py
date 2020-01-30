import re
import sys
import pymysql
import xml

METHOD = re.compile(rb"(POST|GET)")
HOST = re.compile(rb"host\s?:\s?(?P<host> .*)", re.I)
CONTYPE = re.compile(rb"content-type\s?:\s?(?P<contenttype> .*)", re.I)
USERNAME = re.compile(rb"(user|login|m_id|id)[^(&|=)]*=(?P<username>[^(&|=)]*)(&|$|\s|\[)", re.I)
PASSWD = re.compile(rb"(pass|user|pw)[^(&|=)]*=(?P<pass>[^(&|=|[)]*)(&|$|\s|\[)", re.I)

pkt = b'POST /signIn.php/userid=asdf HTTP/1.1\r\nHost: 192.168.0.40\r\nConnection: keep-alive\r\nContent-Length: 23\r\nCache-Control: max-age=0\r\nOrigin: http://192.168.0.40\r\nUpgrade-Insecure-Requests: 1\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nReferer: http://192.168.0.40/logIn.php\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: ko-KR,ko;q=0.9,en;q=0.8\r\n\r\nuserId=asdf&userPw=asdf'

def connect():
    conn = pymysql.connect(
    	host='localhost', 
    	user='jyp', 
    	password='wldbs11', 
    	db='wallofsheep')
    conn.autocommit = True
    cur = conn.cursor()
    return cur

def obfuscate(passwd):
	return passwd[0] + "*" * (len(passwd) - 2) + passwd[-1]

def parsePkt(pkt):
	method = re.findall(METHOD, pkt)
	if not method:
		return None
	method = method[0].decode('utf-8')
	print (method)

	host = re.findall(HOST, pkt)
	if not host:
		return None
	host = host[0].decode('utf-8')
	host = host.strip()
	print(host)
	
	contype = re.findall(CONTYPE, pkt)
	if not contype:
		return None
	contype = contype[0].decode('utf-8')
	contype = contype.strip()
	print(contype)

	if method == "GET":
		userid = re.findall(USERNAME, pkt)
		if not userid:
			return None
		userid = list(userid[0])
		userid = userid[1].decode('utf-8')
		print (userid)
	
		userpw = re.findall(PASSWD, pkt)
		if not userpw:
			return None
		userpw = userpw[0].decode('utf-8')
		print (obfuscate(userpw))
	else:
		if 'urlencoded' in contype:
			print(contype)


def main():
	cur = connect()
	parsePkt(pkt)
	
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