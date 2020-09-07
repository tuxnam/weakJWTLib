from flask import abort, jsonify, make_response, current_app
from datetime import datetime
import logging

logging.basicConfig(filename='errors.log')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def log_error(error):
    """Centralized error logging
    """
    logging.error(str(datetime.now().time())+': '+str(error))

class UserLockedError(Exception):
    """Exception raised for locked user.
    """
    def __init__(self,error):
        self.message = ErrorMessage['UserLockedError']
        log_error(error)
        super().__init__(self.message)

class CryptoError(Exception):
    """Exception raised for error in crypto.
    """
    def __init__(self,error):       
        self.message = ErrorMessage['CryptoError']
        log_error(error)
        super().__init__(self.message)

class InvalidAuthMethodError(Exception):
    """Exception raised for invalid auth method.
    """
    def __init__(self):
        self.message = ErrorMessage['InvalidAuthMethodError']
        log_error(self.message)
        super().__init__(self.message)

class WeakPasswordError(Exception):
    """Exception raised for errors in password complexity.
    """
    def __init__(self):
        self.message = ErrorMessage['WeakPasswordError']
        log_error(self.message)
        super().__init__(self.message)

class UnknownRoleError(Exception):
    """Exception raised for errors in role assignment.
    """
    def __init__(self):
        self.message = ErrorMessage['UnknownRoleError']
        log_error(self.message)
        super().__init__(self.message)

class DatabaseQueryError(Exception):
    """Exception raised for errors against the database.
    """
    def __init__(self, sql_error):
        self.message = ErrorMessage['DatabaseQueryError']
        log_error(sql_error)
        super().__init__(self.message)

class InvalidCredentialsError(Exception):
    """Exception raised for invalid credentials.
    """
    def __init__(self):
        self.message = ErrorMessage['InvalidCredentialsError']
        log_error(self.message)
        super().__init__(self.message)

class InternalServerError(Exception):
    """Exception raised for errors not covered by other exceptions: internal errors.
    """
    def __init__(self,error):
        self.message = ErrorMessage['InternalServerError']
        log_error(error)
        super().__init__(self.message)

class InvalidPrivilegesError(Exception):
    """Exception raised for incorrect privileges.
    """
    def __init__(self):
        self.message = ErrorMessage['InvalidPrivilegesError']
        log_error(self.message)
        super().__init__(self.message)
        
class MissingParameterError(Exception):
    """Exception raised for incorrect privileges.
    """
    def __init__(self):
        self.message = ErrorMessage['MissingParameterError']
        log_error(self.message)
        super().__init__(self.message)
        
class RecordsNotFoundError(Exception):
    """Exception raised for query returning no records.
    """
    def __init__(self):
        self.message = ErrorMessage['RecordsNotFoundError']
        log_error(self.message)
        super().__init__(self.message)

class MultipleRecordsError(Exception):
    """Exception raised for query returning multiple records while 1 is excepted.
    """
    def __init__(self):
        self.message = ErrorMessage['MultipleRecordsError']
        log_error(self.message)
        super().__init__(self.message)

class UserAlreadyExistsError(Exception):
    """Exception raised for adding a username which already exists.
    """
    def __init__(self):
        self.message = ErrorMessage['UserAlreadyExistsError']
        log_error(self.message)
        super().__init__(self.message)


ErrorMessage = {
        'UserAlreadyExistsError':'Error while creating user, user already exists or username is not of expected format.',
        'MultipleRecordsError':'Multiple records exist for the given parameters, only one was expected.',
        'RecordsNotFoundError':'No records found for the given parameters.',
        'MissingParameterError':'Missing or invalid parameters.',
        'InvalidPrivilegesError':'Invalid privileges for the requested operations.',
        'InternalServerError':'An internal error occured, please check your parameters.',
        'InvalidCredentialsError':'Invalid credentials.',
        'DatabaseQueryError':'An internal error occured, please check your parameters.',
        'UnknownRoleError':'Unknown or invalid role provided.',
        'WeakPasswordError':'Password complexity requirements are not met.',
        'InvalidAuthMethodError':'Authentication method selected is invalid or unknown.',
        'CryptoError':'An internal error occured, please check your parameters.',
        'InvalidSignatureError':'The JWT token signature is not using authorized authentication methods for this user.',
        'UserLockerError':'The user is locked.'
    }

