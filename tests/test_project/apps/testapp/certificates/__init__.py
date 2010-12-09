#!/usr/bin/python

from os.path import abspath, dirname, join

CERT_ROOT = abspath(dirname(__file__))

CA_KEY_PATH=join(CERT_ROOT, 'rootca.key')
CA_KEY=open(CA_KEY_PATH, 'r').read()

C_KEY_PATH=join(CERT_ROOT, 'client.key')
C_KEY=open(C_KEY_PATH, 'r').read()

U_KEY_PATH=join(CERT_ROOT, 'user.key')
U_KEY=open(U_KEY_PATH, 'r').read()

C_PUB_KEY_PATH=join(CERT_ROOT, 'client.pub')
C_PUB_KEY=open(C_PUB_KEY_PATH, 'r').read()

CA_CERT_PATH=join(CERT_ROOT, 'rootca.crt')
CA_CERT=open(CA_CERT_PATH, 'r').read()

C_REQUEST_PATH=join(CERT_ROOT, 'client_req.pem')
C_REQUEST=open(C_REQUEST_PATH, 'r').read()

C_CERT_PATH=join(CERT_ROOT, 'client.crt')
C_CERT=open(C_CERT_PATH, 'r').read()

U_REQUEST_PATH=join(CERT_ROOT, 'user_req.pem')
U_REQUEST=open(U_REQUEST_PATH, 'r').read()

U_CERT_PATH=join(CERT_ROOT, 'user.crt')
U_CERT=open(U_CERT_PATH, 'r').read()

UTF8_CERT_PATH=join(CERT_ROOT, 'utf8.pem')
UTF8_CERT=open(UTF8_CERT_PATH, 'r').read()
