from flask import abort, jsonify, make_response
from datetime import datetime
import logging

logging.basicConfig(filename='errors.log')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class DatabaseQueryError(Exception):
    """Exception raised for errors against the database.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        logging.warning(str(datetime.now().time())+': '+str(message))
        abort(make_response(jsonify(error=['An error occured with your request, please check your parameters.']), 400))

class InternalServerError(Exception):
    """Exception raised for errors not covered by other exceptions: internal errors.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        logging.error(str(datetime.now().time())+': '+str(message))
        abort(make_response(jsonify(error=['']), 400))

class RecordsNotFoundError(Exception):
    """Exception raised for query returning no records.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        logging.error(str(datetime.now().time())+': '+str(message))
        abort(make_response(jsonify(error=['']), 204))

class MultipleRecordsError(Exception):
    """Exception raised for query returning multiple records while 1 is excepted.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        logging.error(str(datetime.now().time())+': '+str(message))
        abort(make_response(jsonify(error=['']), 204))

class UnauthorizedError(Exception):
    pass
