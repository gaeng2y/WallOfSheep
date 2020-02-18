#!/usr/bin/python3

import re
import pymysql
import sniff

METHOD = re.compile(rb"(POST|GET)")
HOST = re.compile(rb"host\s?:\s?(?P<host>[^(\r)]*)", re.I)
CONTYPE = re.compile(rb"content-type\s?:\s?(?P<contenttype>[^(\r)]*)", re.I)
USERNAME = re.compile(rb"(os_id|userid|user_id|name)[^(&|=)]*=(?P<username>[^(&|=)]*)", re.I)
PASSWD = re.compile(rb"(pass|userpw|pw|user_pw)[^(&|=)]*=(?P<pass>[^(&|=|\')]*)", re.I)

def obfuscate(passwd):
	passwd = passwd.decode()
	return passwd[0] + "*" * (len(passwd) - 2) + passwd[-1]

def insertInfo(conn, cur, id, pw, ip, host, mac, protocol):
	query = 'INSERT into wos (id, pw, host, ip, mac, protocol) values(%s, %s, %s, %s, %s, %s)'
	cur.execute(query, (id, pw, host, ip, mac, protocol))
	conn.commit()
	print("Success Info Insert\n")

def cntHost(conn, cur, host):
	initcnt = 1
	query = 'SELECT EXISTS (SELECT * FROM count WHERE host = %s) as success'
	cur.execute(query, host)
	res = cur.fetchall()
	res = res[0][0]
	if (res == 0):
		query = 'INSERT into count (host, count) values(%s, %s)'
		cur.execute(query, (host, initcnt))
		conn.commit()
		print("Insert Count Success\n")
	else:
		query = 'SELECT count FROM count WHERE host = %s'
		cur.execute(query, host)
		cnt = cur.fetchall()
		cnt = cnt[0][0]
		cnt += 1
		query = 'UPDATE count SET count = %s WHERE host = %s'
		cur.execute(query, (cnt, host))
		conn.commit()
		print("Update Count Success\n")

def parsePkt(pkt):
	# host parse
	print(pkt)
	host = re.search(HOST, pkt)
	if not host:
		return None
	host = host.groups()[0]
	host = host.decode()

	# method call
	method = re.search(METHOD, pkt)
	if not method:
		return None
	method = method.groups()[0]

	# get
	if method == b'GET':
		userid = re.search(USERNAME, pkt)
		if not userid:
			return None
		userid = userid.groups()[1]
		#print(userid)

		userpw = re.search(PASSWD, pkt)
		if not userpw:
			return None
		userpw = userpw.groups()[1]

	# post => last value
	else:
		contype = re.search(CONTYPE, pkt)
		contype = contype.groups()[0]

		if b'urlencoded' in contype:
			userid = re.findall(USERNAME, pkt)
			if not userid:
				return None
			userid = userid[-1][-1]
			
			userpw = re.findall(PASSWD, pkt)
			if not userpw:
				return None
			userpw = userpw[-1][-1]
		elif b'text/plain' in contype:
			pass

		elif b'json' in contype:
			pass

	return (userid, userpw, obfuscate(userpw), host)

def main():
	conn = pymysql.connect(host='localhost', user='jyp', password='wldbs11', db='wallofsheep', charset='utf8')
	cur = conn.cursor()
	
	while(True):
		pkt, ip, mac, protocol = sniff.sniff("wlan1")
		print()
		rlt = parsePkt(pkt)
		if rlt is not None:
			uid, upw, obsupw, host = rlt[0],rlt[1], rlt[2], rlt[3]
			try:
				print("ID: ", uid.decode(), "\nPW: ", upw.decode(), "\nHost: ", host, "\nIP: ", ip, "\nMAC Address: ", mac, "\nProtocol: ", protocol)
				insertInfo(conn, cur, uid, obsupw, ip, host, mac, protocol)
				cntHost(conn, cur, host)
			except Exception:
				pass

	conn.close()

	
if __name__ == "__main__":
	main()

