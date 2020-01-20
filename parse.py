import re
import sys
import sqlite3

con = sqlite3.connect('./test.db')
cur = con.cursor()

USERNAME = re.compile(r"(id|login|m_id|user)[^(&|=)]*=(?P<username>[^(&|=)]*)(&|$|\s|\[)", re.I)
PASSWD = re.compile(r"(pass|user)[^(&|=)]*=(?P<pass>[^(&|=|[)]*)(&|$|\s|\[)", re.I)

pkg = """
POST /memberLogin.es?mid=a10701010000&category=act HTTP/1.1
Host: www.joongbu.ac.kr
Connection: close
Content-Length: 184
Cache-Control: max-age=0
Origin: https://www.joongbu.ac.kr
Upgrade-Iensecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
Sec-Fetch-User: ?1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Referer: https://www.joongbu.ac.kr/memberLogin.es?mid=a10701010000
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: __utmz=33484581.1564635341.26.2.utmcsr=ipsi.joongbu.ac.kr|utmccn=(referral)|utmcmd=referral|utmcct=/; _ga=GA1.3.126462132.1550649656; __utma=33484581.126462132.1550649656.1568021785.1570439261.32; optimizelyEndUserId=oeu1575253964827r0.6941755656554796; amplitude_id_9f6c0bb8b82021496164c672a7dc98d6_edmjoongbu.ac.kr=eyJkZXZpY2VJZCI6IjNmNzA4YzAwLWMxOGMtNDdjYi1iMzk3LWU3ZDRkMGExODUyNCIsInVzZXJJZCI6bnVsbCwib3B0T3V0IjpmYWxzZSwic2Vzc2lvbklkIjoxNTc1MjUzOTY3OTUxLCJsYXN0RXZlbnRUaW1lIjoxNTc1MjUzOTkxNzkyLCJldmVudElkIjowLCJpZGVudGlmeUlkIjoyLCJzZXF1ZW5jZU51bWJlciI6Mn0=; amplitude_id_408774472b1245a7df5814f20e7484d0joongbu.ac.kr=eyJkZXZpY2VJZCI6IjNmNzA4YzAwLWMxOGMtNDdjYi1iMzk3LWU3ZDRkMGExODUyNCIsInVzZXJJZCI6bnVsbCwib3B0T3V0IjpmYWxzZSwic2Vzc2lvbklkIjoxNTc1MjUzOTY3MjAzLCJsYXN0RXZlbnRUaW1lIjoxNTc1MjUzOTkxODkwLCJldmVudElkIjo0LCJpZGVudGlmeUlkIjoxMCwic2VxdWVuY2VOdW1iZXIiOjE0fQ==; WMONID=M_6VnNJ1ZBP; XSRF-TOKEN=7067db61-7077-4396-8efc-8d44d349b2ef; JSESSIONID=aaaKsOUIDJVDPbfTQNQ9wvQo4M1hGrjgepYDIUGzEm9_YpsmTl29abTl5pg8

returnURL=https%3A%2F%2Fwww.joongbu.ac.kr%2Fhome%2F&req_returnUrl=https%3A%2F%2Fwww.joongbu.ac.kr%2Fhome%2F&m_id=91714313&passwd=testtest&_csrf=7067db61-7077-4396-8efc-8d44d349b2ef
"""

def parsePkg(pkg):
	ip = '127.0.0.1'
	pog = pkg[1]

	#hostStart = pkg.find("Host:")
	#lastDomain = pkg.index("Connection:")
	#hostName = pkg[(hostStart)+6:(lastDomain)-1]
	hostName = "www.joongbu.ac.kr"

	contentTypeF = pkg.find("Content-Type: ")
	contentTypeL = pkg.find("User-Agent")
	contentType = pkg[(contentTypeF+14):(contentTypeL)-1]
	print(contentType)

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

	cur.execute('INSERT INTO wos (id, pw, ip, host, cookie) VALUES(?, ?, ?, ?, ?);', (userID, userPW, ip, hostName, cookie))
	con.commit()

parsePkg(pkg)