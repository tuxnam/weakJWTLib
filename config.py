class Config(object):
    DEBUG = False
    TESTING = False
    DATABASE_NAME = 'database.db'
    SUPPORTED_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] 
    SUPPORTED_AUTHENTICATION = ['JWT-SYM', 'JWT-RSA']
    SYMMETRIC_KEY = 'mySupertopawfulhardcodedMEGASecretISHEre!!!'.encode('utf-8')
    JWT_PUBLIC_KEY = open('keys/rsa.public').read()
    JWT_PRIVATE_KEY = open('keys/rsa.private').read()
    ROLES_LIST = ['OPERATOR', 'AUDITOR', 'ADMIN']
