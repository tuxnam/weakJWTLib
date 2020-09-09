from flask import Flask, request, abort, jsonify
from auth_utils import restricted, dict_from_row
from errors import *
from datetime import timedelta, datetime
from crypto_utils import encrypt_password, verif_password
import sqlite3 as sql
import jwt
import json
import config
import base64

app = Flask(__name__)
app.config.from_object('config.Config')

## Set role for a user with a specific UID
@app.route('/user/<int:uid>/role', methods=['PUT'])
@restricted(access_level='ADMIN')
def setRole(uid):
    try:
        con = sql.connect("database.db")
        role = request.json.get('role')

        if (role is None) or (role.upper() not in app.config['ROLES_LIST']):
            raise UnknownRoleError()

        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE ID=(?)",(uid,))
        rows = cur.fetchall()

        dict = []
        for row in rows:
            dict.append(dict_from_row(row))

        if len(dict) < 1:
            raise RecordsNotFoundError()

        if len(dict) > 1:
            raise MutipleRecordsError()

        cur.execute("UPDATE Users SET ROLE=(?) WHERE ID=(?)",(role, str(uid),))
        con.commit()

        return {'Message':'User successfuly updated, number of rows updated: '+str(cur.rowcount)}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except (RecordsNotFoundError, MultipleRecordsError, UnknownRoleError) as error:
        return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 400, {'ContentType':'application/json'}
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        if con:
            con.close()

## Create user 
@app.route('/user', methods=['POST'])
##@restricted(access_level='ADMIN')
def register():
    try:
        con = sql.connect(app.config['DATABASE_NAME'])
        con.row_factory = sql.Row
        data = []
        cur = con.cursor()
        authMethod = request.json.get('authMethod')
        username = request.json.get('username')
        password = request.json.get('password')
        role = request.json.get('role')

        if (username is None) or (password is None) or (authMethod is None) or (role is None):
            raise MissingParameterError()

        if (len(username) <= 2):
            raise RecordsNotFoundError() 

        if (len(password) < 8):
            raise WeakPasswordError()
        
        if (authMethod not in app.config['SUPPORTED_AUTHENTICATION']):
            raise InvalidAuthMethodError()

        password = encrypt_password(password)
                
        cur.execute("SELECT * FROM Users WHERE USERNAME=(?)",(username,))
        rows = cur.fetchall()

        dict = []
        for row in rows:
            dict.append(dict_from_row(row))

        if len(dict) >= 1:
            raise UserAlreadyExistsError()
        
        cur.execute("INSERT INTO Users (USERNAME, PASSWORD, AUTHMETHOD, ROLE, LOCKED) VALUES (?,?,?,?,?)",(username, str(password), authMethod, role, 0, ))
        con.commit()

        return {'Message':'User successfuly created'}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except (UserAlreadyExistsError, InvalidAuthMethodError, WeakPasswordError, RecordsNotFoundError, MissingParameterError) as error:
        return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 400, {'ContentType':'application/json'}
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        if con:
            con.close()

## List all users
@app.route('/users', methods=['GET'])
@restricted(access_level='AUDITOR')
def listUsers():
    try:
        con = sql.connect(app.config['DATABASE_NAME'])
        con.row_factory = sql.Row
        data = []
        cur = con.cursor()
        cur.execute("select * from Users")

        rows = cur.fetchall()
        for row in rows:
            data.append([x for x in row]) 

        return json.dumps(data), 200

    except sql.Error as sql_error: 
        raise DatabaseQueryError()
    except Exception as exception:
        raise InternalServerError()

## Untrusted auth is based on RS256 (asymmetric key) - Case where you do not control the endpoint receiving the token: browsers, mobile appliations...
## Trusted auth is based on HS256 (symmetric key) - Case where you have control of the endpoint receiving the token
@app.route('/basicAuth', methods=['POST'])
def authForClients():
       
    try:
       con = sql.connect('database.db')
       username = request.json.get('username')
       password = request.json.get('password')
       encodedJWT = ''

       if username is None or password is None:
           raise InvalidCredentialsError()  
                   
       con.row_factory = sql.Row
       cur = con.cursor()
       cur.execute("select ID,USERNAME,PASSWORD,AUTHMETHOD,EMAIL,LOCKED from Users where USERNAME=?",(username,))
       rows = cur.fetchall()
      
       dict = []
       for row in rows:
           dict.append(dict_from_row(row))
       
       if len(dict) < 1:
           raise InvalidCredentialsError()

       if len(dict) > 1:
           raise MutipleRecordsError()

       # Check password
       if not verif_password(password,dict[0]['PASSWORD']):
           raise InvalidCredentialsError()
       
       # User is locked?
       if dict[0]['LOCKED'] == 1:
           raise UserLockedError()
    
       # optional elements:
       if dict[0]['EMAIL'] is None:
           dict[0]['EMAIL'] = ''

       payload = {
               'exp': datetime.utcnow() + timedelta(days=1),
               'iat': datetime.utcnow(),
               'nbf': datetime.utcnow(),
               'user_uid': dict[0]['ID'],
               'user_email': base64.b64encode(dict[0]['EMAIL'].encode('utf-8')).decode('utf-8')
       }

       if dict[0]['AUTHMETHOD'] not in app.config['SUPPORTED_AUTHENTICATION']:
           raise InvalidAuthMethodError()

       if dict[0]['AUTHMETHOD'] == 'JWT-RSA':
           encodedJWT = jwt.encode(payload, app.config['JWT_PRIVATE_KEY'], algorithm='RS256')
       else:
           ##JWT-SYM                
           encodedJWT = jwt.encode(payload, app.config['SYMMETRIC_KEY'], algorithm='HS256')

       return jsonify(JWT=encodedJWT.decode('utf-8')), 200 

    except sql.Error as sql_error:                           
        raise DatabaseQueryError(sql_error)
    except (InvalidCredentialsError, UserLockedError) as error:
        return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 403,  {'ContentType':'application/json'}
    except (InvalidAuthMethodError,MultipleRecordsError) as error:
        return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 400, {'ContentType':'application/json'}
    except Exception as e: 
        raise InternalServerError(e)
    finally:
        if con:
            con.close()

##User update based on username
@app.route('/user/<string:username>', methods=['PUT'])
@restricted(access_level='ADMIN')
def updateUserByUsername(username):

    try:
        authmethod = request.json.get('authMethod')

        con = sql.connect(app.config['DATABASE_NAME'])
        data = []
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE username=(?)",(username,))
        rows = cur.fetchall()

        dict = []
        for row in rows:
            dict.append(dict_from_row(row))

        if len(dict) < 1:
            raise RecordsNotFoundError()

        if len(dict) > 1:
            raise MutipleRecordsError()

        #rowcount is == 1
        #checking current values for this user
        if (dict[0]['AUTHMETHOD'] == authmethod) or (authmethod is None):
            authmethod = dict[0]['AUTHMETHOD']

        cur.execute("UPDATE Users SET AUTHMETHOD=(?) WHERE USERNAME=(?)",(authmethod, username,))
        con.commit()

        return {'Message':'User successfuly updated, number of rows updated: '+str(cur.rowcount)}, 200, {'ContentType':'application/json'}

    except sql.Error as sql_error:
        raise DatabaseQueryError(sql_error)
    except(RecordsNotFoundError,MultipleRecordsError) as error:
        return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 400, {'ContentType':'application/json'}
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        con.close()

##User update based on UID
@app.route('/user/<int:uid>', methods=['PUT'])
@restricted(access_level='ADMIN')
def updateUserByUID(uid):

    try:
        username = request.json.get('username')
        authmethod = request.json.get('authMethod')

        con = sql.connect(app.config['DATABASE_NAME'])
        data = []
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE ID=(?)",(str(uid),))
        rows = cur.fetchall()

        dict = []
        for row in rows:
            dict.append(dict_from_row(row))
    
        if len(dict) < 1:
            raise RecordsNotFoundError()  
    
        if len(dict) > 1:
            raise MutipleRecordsError() 

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
    except (RecordsNotFoundError, MultipleRecordsError) as error:
        return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 400, {'ContentType':'application/json'}
    except Exception as exception:
        raise InternalServerError(exception)
    finally:
        if con:
            con.close()
    
##List users based on username
@app.route('/user/<string:username>', methods=['GET'])
@restricted(access_level='AUDITOR')
def listUsersByUsername(username):

    data = []
    try:
        con = sql.connect(app.config['DATABASE_NAME'])
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
@restricted(access_level='AUDITOR')
def listUsersByUID(uid):
    
    data = []
    try:
        con = sql.connect(app.config['DATABASE_NAME'])
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

