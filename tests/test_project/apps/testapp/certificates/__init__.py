#!/usr/bin/python

from os.path import abspath, dirname, join

CERT_ROOT = abspath(dirname(__file__))

CA_KEY=open(join(CERT_ROOT, 'rootca.key'), 'r').read()

C_KEY=open(join(CERT_ROOT, 'client.key'), 'r').read()

U_KEY=open(join(CERT_ROOT, 'user.key'), 'r').read()

C_PUB_KEY=open(join(CERT_ROOT, 'client.pub'), 'r').read()

CA_CERT=open(join(CERT_ROOT, 'rootca.crt'), 'r').read()

C_REQUEST=open(join(CERT_ROOT, 'client_req.pem'), 'r').read()

C_CERT=open(join(CERT_ROOT, 'client.crt'), 'r').read()

U_REQUEST=open(join(CERT_ROOT, 'user_req.pem'), 'r').read()

U_CERT=open(join(CERT_ROOT, 'user.crt'), 'r').read()
