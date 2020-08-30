import sqlite3

conn = sqlite3.connect('database.db')
print ('Opened database successfully')

conn.execute('CREATE TABLE users (USERNAME TEXT NOT NULL, PASSWORD TEXT NOT NULL, AUTHMETHOD TEXT NOT NULL, LOCKED INTEGER NOT NULL DEFAULT 0, ID INTEGER PRIMARY KEY AUTOINCREMENT, ROLE TEXT NOT NULL DEFAULT "Regular")')
print ('Table created successfully')
conn.close()
