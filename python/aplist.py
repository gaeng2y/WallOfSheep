def aplist(conn, cur, mac, name):
    query = "INSERT INTO wos (mac, name) values(%s, %s)"
    cur.execute(query, (mac, name))
    conn.commit()
    cur.execute("SELECT * FROM wos")
    res = cur.fetchall()
    print(res)
