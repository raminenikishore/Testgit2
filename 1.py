import os
import sys
import sqlite3
conn = sqlite3.connect("C:\\sqlite\\newdb.sqlite")
conn.row_factory=sqlite3.Row
cursor=conn.cursor()
cursor.execute("""create table if not exists logstack (lid INTEGER PRIMARY KEY AUTOINCREMENT, timestamp VARCHAR, severity VARCHAR, spno VARCHAR,
 sip VARCHAR, protocol VARCHAR, cve VARCHAR)""")
with open(r"log.txt") as f:
    for line in f:
      var1=line.split()[0]+" "+line.split()[1]
      var2=line.split()[2]
      var3=line.split()[3]
      var4=line.split()[4]
      var5=line.split()[5]
      try:
         var6= line.split()[6]
      except:
         var6="!!!NULL!!! "
      query="insert into logstack (timestamp,severity,spno,sip,protocol,cve) values(?,?,?,?,?,?)"
      t=(var1,var2,var3,var4,var5,var6)
      cursor.execute(query,t)
      conn.commit()
    query1="select count(*) from logstack where cve LIKE '%CVE%' and severity='critical'";
    cursor.execute(query1)
    print (cursor.fetchone()[0])
    rows=cursor.fetchall()
    count=0;
    for row in rows:
        if row:
         print ("the number of critical CVE events are :" +str(row))
         print ("the number of critical CVE events are :" +str(row[0]))