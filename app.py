from flask import Flask, request, abort, jsonify
import sqlite3 as sql
import jwt
import json
import datetime
import base64

app = Flask(__name__)
app.config['SUPPORTED_ALGORITHMS'] = ['HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384',
                                      'RS512', 'PS256', 'PS384', 'PS512']
app.config['SYMMETRIC_KEY'] = 'key'


@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.json.get('username')
        password = request.json.get('password')
        
        if username is None or password is None:
            abort(400)  # missing arguments
    
        with sql.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO Users (USERNAME, PASSWORD) VALUES (?,?)",(username, password))
            con.commit()
            msg = "User successfully created!"
    except: 
        msg = "Error while adding user!"
    finally:
        return json.dumps({msg:True}), 200, {'ContentType':'application/json'}

@app.route('/list', methods=['GET'])
def list():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    data = []
    cur = con.cursor()
    cur.execute("select * from Users")

    rows = cur.fetchall()
    for row in rows:
        data.append([x for x in row]) 

    return json.dumps(data)
        

@app.route('/auth', methods=['POST'])
def auth():
       username = request.json.get('username')
       password = request.json.get('password')
       encodedJWT = ''

       if username is None or password is None:
           abort(400)  # missing arguments

       con = sql.connect('database.db')
       con.row_factory = sql.Row
       cur = con.cursor()
       cur.execute("select ID,USERNAME from Users where USERNAME=? and PASSWORD=?",(username,password))
       rows = cur.fetchall()
       con.close()
       
       data = []
       for row in rows:
            data.append([x for x in row])
       
       payload = {
               'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=5),
               'iat': datetime.datetime.utcnow(),
               'sub': data[0],
               'nbf': datetime.datetime.utcnow() - datetime.timedelta(days=1, seconds=5)
       }
           
       encodedJWT = jwt.encode(payload,'key',algorithm='HS256')

                         
       return encodedJWT, 200, {'ContentType':'application/json'}


@app.route('/decode', methods=['POST'])
def decode():
    authHeader = request.headers['Authorization']
    if (authHeader is None) or (authHeader.startswith('JWT')):
        encodedJWT = authHeader.split('JWT ')
    else:
        raise Exception(
            'JWT in Authorization header mal-formatted or missing!', status_code=403)

    decoded = jwt.decode(
            encodedJWT[1], 'key')

    return decoded, 200, {'ContentType':'application/json'}


if __name__ == '__main__':
    app.run()
