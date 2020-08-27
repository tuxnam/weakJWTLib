from flask import Flask, request, abort, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sqlite3 as sql
import jwt
import json
import datetime
import base64
from auth_utils import jwt_protected
from jwt.algorithms import RSAAlgorithm
from errors import *

app = Flask(__name__)
app.config['SUPPORTED_ALGORITHMS'] = ['HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384',
                                      'RS512', 'PS256', 'PS384', 'PS512']
app.config['SUPPORTED_AUTHENTICATION'] = ['JWT-SHA2', 'JWT-RSA']
app.config['SYMMETRIC_KEY'] = 'mySuperSeretKeyHostedSoSecurely!1234'
app.config['JWT_PUBLIC_KEY'] = open('keys/rsa.public').read()
app.config['JWT_PRIVATE_KEY'] = open('keys/rsa.private').read()

def dict_from_row(row):
    return dict(zip(row.keys(), row)) 

@app.route('/register', methods=['POST'])
def register():
    try:
        error = 0
        msg = ''
        username = request.json.get('username')
        password = request.json.get('password')
        authMethod = request.json.get('authMethod')

        if (username is None) or (password is None) or (authMethod is None):
            error=1
            msg='Missing or empty required parameter. Required parameters are (username, password, authMethod'
 
        if (len(username) <= 2):
            error=1
            msg='Username must be at least three characters long'

        if (len(password) <= 8):
            error=1
            msg='Weak password'

       
        if (authMethod not in app.config['SUPPORTED_AUTHENTICATION']):
            error=1
            msg='unsupported authentication method. Supported methods are: JWT-SHA2 or JWT-RSA'
        
        with sql.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO Users (USERNAME, PASSWORD, AUTHMETHOD, LOCKED) VALUES (?,?,?,?)",(username, password, authMethod,0))
            con.commit()
            msg = "User successfully created!"
    except: 
        error=1
        msg = "Error while adding user!"
    finally:
        if error==1:
            return json.dumps({'Error':msg}), 400, {'ContentType':'application/json'}  
        else:
            return json.dumps({'Message':msg}), 200, {'ContentType':'application/json'}


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
    
## Untrusted auth is based on RS256 (asymmetric key) - Case where you do not control the endpoint receiving the token: browsers, mobile appliations...
@app.route('/untrustedAuth', methods=['POST'])
def untrustedAuth():
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

       encodedJWT = jwt.encode(payload, key=app.config['JWT_PRIVATE_KEY'], algorithm='RS256')


       return encodedJWT, 200, {'ContentType':'application/json'}

## Trusted auth is based on HS256 (symmetric key) - Case where you have control of the endpoint receiving the token
@app.route('/trustedAuth', methods=['POST'])
def authForTrustedClients():
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
           
       encodedJWT = jwt.encode(payload, app.config['SYMMETRIC_KEY'], algorithm='HS256')

                         
       return encodedJWT, 200, {'ContentType':'application/json'}


##User update based on UID
@app.route('/user/<int:uid>', methods=['PUT'])
##@jwt_protected
def updateUserByUID(uid):

    try:
        username = request.json.get('username')
        authmethod = request.json.get('authMethod')

        con = sql.connect("database.db")
        data = []
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE ID=(?)",(str(uid),))
        rows = cur.fetchall()

        dict = []
        for row in rows:
            dict.append(dict_from_row(row))
    
        if len(dict) < 1:
            raise RecordsNotFoundError('No user with this UID was found!')  
    
        if len(dict) > 1:
            raise MutipleRecordsError('The user table seems to be corrupted, several users found for the same ID!') 

        #rowcount is == 1
        #checking current values for this user
        if (dict[0]['USERNAME'] == username) or (username is None):
            username = dict[0]['USERNAME']
    
        if (dict[0]['AUTHMETHOD'] == authmethod) or (authmethod is None):
            authmethod = dict[0]['AUTHMETHOD']

        cur.execute("UPDATE Users SET USERNAME=(?), AUTHMETHOD=(?) WHERE ID=(?)",(username, authmethod, str(uid),))
        con.commit()
        
        return {'Message':'User successfuly updated, number of rows updated: '+str(cur.rowcount)}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except:
        raise InternalServerError(sys.exc_info()[0])
    finally:
        if con:
            con.close()

    
##List users based on UID
@app.route('/user/<int:uid>', methods=['GET'])
@jwt_protected
def listUsers(uid):
    
    data = []
    try:
        con = sql.connect("database.db")
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE ID=(?)",(str(uid),))
        rows = cur.fetchall()
    
        for row in rows:
            data.append([x for x in row])

        return json.dumps(data), 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error) 
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        if con:
            con.close()
    

if __name__ == '__main__':
    app.run()
