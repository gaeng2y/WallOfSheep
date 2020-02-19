def aplist(conn, cur, mac, name):
    query = "INSERT INTO ap (mac, name) values(%s, %s)"
    cur.execute(query, (mac, name))
    conn.commit()
    cur.execute("SELECT * FROM ap")
    res = cur.fetchall()
    print(res)
