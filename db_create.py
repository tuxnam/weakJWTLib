import sqlite3

conn = sqlite3.connect('database.db')
print ('Opened database successfully')

conn.execute('CREATE TABLE users (ID INTEGER PRIMARY KEY AUTOINCREMENT, USERNAME TEXT NOT NULL, PASSWORD TEXT NOT NULL, AUTHMETHOD TEXT NOT NULL, LOCKED INTEGER NOT NULL DEFAULT 0, ROLE TEXT NOT NULL DEFAULT "Regular", EMAIL TEXT)')
print ('Table created successfully')
conn.close()
