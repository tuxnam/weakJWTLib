from flask import Flask, request, abort, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from auth_utils import jwt_protected
from jwt.algorithms import RSAAlgorithm
from errors import *
from datetime import timedelta
import sqlite3 as sql
import jwt
import json
import datetime
import base64

app = Flask(__name__)
app.config['SUPPORTED_ALGORITHMS'] = ['HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384',
                                      'RS512', 'PS256', 'PS384', 'PS512']
app.config['SUPPORTED_AUTHENTICATION'] = ['JWT-SYM', 'JWT-RSA']
app.config['SYMMETRIC_KEY'] = 'mySupertopawfulhardcodedMEGASecretISHEre!!!'
app.config['JWT_PUBLIC_KEY'] = open('keys/rsa.public').read()
app.config['JWT_PRIVATE_KEY'] = open('keys/rsa.private').read()
app.config['ROLES_LIST'] = ['REGULAR', 'AUDITOR', 'ADMIN']

## Return dict from row
def dict_from_row(row):
    return dict(zip(row.keys(), row)) 

#@jwt_protected
@app.route('/user/<int:uid>/role', methods=['PUT'])
def setRole(uid):
    try:
        role = request.json.get('role')
        
        if role not in app.config['ROLES_LIST']:
            raise UnknownRoleError('This role is not supported.')

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

        cur.execute("UPDATE Users SET ROLE=(?) WHERE ID=(?)",(role, str(uid),))
        con.commit()

        return {'Message':'User successfuly updated, number of rows updated: '+str(cur.rowcount)}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        con.close()

@app.route('/user', methods=['POST'])
def register():
    try:
        con = sql.connect("database.db")
        con.row_factory = sql.Row
        data = []
        cur = con.cursor()

        username = request.json.get('username')
        password = request.json.get('password')
        authMethod = request.json.get('authMethod')
        role = request.json.get('role')

        if (username is None) or (password is None) or (authMethod is None) or (role is None):
            raise MissingParameterError('Missing required parameter!')

        if (len(username) <= 2):
            raise RecordsNotFoundError('No user with this username was found!') 

        if (len(password) <= 8):
            raise WeakPasswordError('Password is not complex enough!')

        if (authMethod not in app.config['SUPPORTED_AUTHENTICATION']):
            raise InvalidAuthMethodError('This authentication method is not supported!')

        cur.execute("INSERT INTO Users (USERNAME, PASSWORD, AUTHMETHOD, ROLE, LOCKED) VALUES (?,?,?,?,?)",(username, password, authMethod, role, 0, ))
        con.commit()

        return {'Message':'User successfuly created'}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        con.close()

@app.route('/users', methods=['GET'])
@jwt_protected
def listUsers():
    try:
        con = sql.connect("database.db")
        con.row_factory = sql.Row
        data = []
        cur = con.cursor()
        cur.execute("select * from Users")

        rows = cur.fetchall()
        for row in rows:
            data.append([x for x in row]) 

        return json.dumps(data), 200

    except sql.Error as sql_error: 
        raise DatabaseQueryError(sql_error)
    except Exception as exception:
        raise InternalServerError(exception)

## Untrusted auth is based on RS256 (asymmetric key) - Case where you do not control the endpoint receiving the token: browsers, mobile appliations...
## Trusted auth is based on HS256 (symmetric key) - Case where you have control of the endpoint receiving the token
@app.route('/basicAuth', methods=['POST'])
def authForClients():
       
    try:
       username = request.json.get('username')
       password = request.json.get('password')
       encodedJWT = ''

       if username is None or password is None:
           raise InvalidCredentialsError('Invalid Credentials')  
    
       con = sql.connect('database.db')
       con.row_factory = sql.Row
       cur = con.cursor()
       cur.execute("select ID,USERNAME,AUTHMETHOD from Users where USERNAME=? and PASSWORD=?",(username,password))
       rows = cur.fetchall()
       con.close()

       dict = []
       for row in rows:
           dict.append(dict_from_row(row))
        
       if len(dict) < 1:
           raise InvalidCredentialsError('Invalid credentals!')

       if len(dict) > 1:
           raise MutipleRecordsError('The user table seems to have several users found for the same username/password tuple!')
       
       payload = {
               'exp': datetime.utcnow() + timedelta(days=1),
               'iat': datetime.utcnow(),
               'nbf': datetime.utcnow()
       }

       if dict[0]['AUTHMETHOD'] not in app.config['SUPPORTED_AUTHENTICATION']:
           raise InvalidAuthenticationTypeError('Invalid authentication type!')

       if dict[0]['AUTHMETHOD'] == 'JWT-RSA':
           encodedJWT = jwt.encode(payload, app.config['JWT_PRIVATE_KEY'], algorithm='RS256')
       else:
           ##JWT-SYM                 
           encodedJWT = jwt.encode(payload, app.config['SYMMETRIC_KEY'], algorithm='HS256')

       return jsonify(JWT=encodedJWT.decode('utf-8')), 200 

    except sql.Error as sql_error:                           
        raise DatabaseQueryError(sql_error)
    except Exception as exception: 
        raise InternalServerError(exception)
    finally:
        if con:
            con.close()

##User update based on username
@app.route('/user/<string:username>', methods=['PUT'])
@jwt_protected
def updateUserByUsername(username):

    try:
        authmethod = request.json.get('authMethod')

        con = sql.connect("database.db")
        data = []
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE username=(?)",(username,))
        rows = cur.fetchall()

        dict = []
        for row in rows:
            dict.append(dict_from_row(row))

        if len(dict) < 1:
            raise RecordsNotFoundError('No user with this username was found!')

        if len(dict) > 1:
            raise MutipleRecordsError('The user table seems to have several users found for the same username!')

        #rowcount is == 1
        #checking current values for this user
        if (dict[0]['AUTHMETHOD'] == authmethod) or (authmethod is None):
            authmethod = dict[0]['AUTHMETHOD']

        cur.execute("UPDATE Users SET AUTHMETHOD=(?) WHERE USERNAME=(?)",(authmethod, username,))
        con.commit()

        return {'Message':'User successfuly updated, number of rows updated: '+str(cur.rowcount)}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except Exception as exception:
        raise InternalServerError(sys.exc_info()[0])
    finally:
        con.close()

##User update based on UID
@app.route('/user/<int:uid>', methods=['PUT'])
@jwt_protected
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
    except Exception as exception:
        raise InternalServerError(sys.exc_info()[0])
    finally:
        if con:
            con.close()

    
##List users based on username
@app.route('/user/<string:username>', methods=['GET'])
@jwt_protected
def listUsersByUsername(username):

    data = []
    try:
        con = sql.connect("database.db")
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE USERNAME=(?)",(username,))
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

##List users based on UID
@app.route('/user/<int:uid>', methods=['GET'])
@jwt_protected
def listUsersByUID(uid):
    
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

