import sqlite3

conn = sqlite3.connect('database.db')
print ('Opened database successfully')

conn.execute('CREATE TABLE users (USERNAME TEXT NOT NULL, PASSWORD TEXT NOT NULL, ID INTEGER PRIMARY KEY AUTOINCREMENT)')
print ('Table created successfully')
conn.close()
