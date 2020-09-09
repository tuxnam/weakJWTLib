from functools import wraps
from flask import request, redirect, url_for, current_app
from errors import *
import jwt
import sqlite3 as sql

def dict_from_row(row):
    return dict(zip(row.keys(), row))

def restricted(access_level):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
                     
            try:
                con = sql.connect(current_app.config['DATABASE_NAME'])
                authHeader = request.headers['Authorization']

                if (authHeader is not None) and (authHeader.startswith('Bearer')):
                    unverified_decoded = jwt.decode(authHeader.split('Bearer')[1].strip(), verify=False)
                else:
                    raise InvalidCredentialsError()

                con.row_factory = sql.Row
                cur = con.cursor()
                cur.execute("SELECT * FROM Users WHERE ID=(?)",(unverified_decoded['user_uid'],))
                rows = cur.fetchall()
                
                dict = []
                for row in rows:
            	    dict.append(dict_from_row(row))

                if len(dict) < 1:
                    raise RecordsNotFoundError()

                if len(dict) > 1: 
                    raise MultipleRecordsError()

                # Check if user has the correct authentication method used for JWT
                if (dict[0]['AUTHMETHOD'] == 'JWT-SYM'):
                    jwt_key = current_app.config['SYMMETRIC_KEY']
                else:
                    jwt_key = current_app.config['JWT_PUBLIC_KEY']
                
                decoded = jwt.decode(authHeader.split('Bearer ')[1].strip(), jwt_key, algorithms=current_app.config['SUPPORTED_ALGORITHMS'])    

                # ADMIN required
                if access_level.upper() == 'ADMIN':
                    if ((dict[0]['ROLE']).upper()) == access_level.upper():
                        return func(*args, **kwargs)
                
                # Minimum level required (auditor)
                if access_level.upper() == 'AUDITOR':
                    return func(*args, **kwargs)

                # At least operator level required (ADMIN and OPERATOR both valids)
                if access_level.upper() == 'OPERATOR':
                    if (((dict[0]['ROLE']).upper()) == 'OPERATOR') or (((dict[0]['ROLE']).upper()) == 'ADMIN'):
                        return func(*args, **kwargs)
                    else:
                        raise InvalidPrivilegesError() 

            except sql.Error as sql_error:
                raise DatabaseQueryError(sql_error)
            except jwt.InvalidSignatureError as error:
                raise InvalidSignatureError(error)
            except InvalidSignatureError as error:
                return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 403, {'ContentType':'application/json'}
            except (InvalidPrivilegesError, RecordsNotFoundError, MultipleRecordsError, InvalidCredentialsError) as error:
                return {'Message':ErrorMessage[str(error.__class__.__name__)]}, 403, {'ContentType':'application/json'} 
            except Exception as exception:
                raise InternalServerError(exception)
            finally:
                if con:
                    con.close()
        return wrapper
    return decorator
