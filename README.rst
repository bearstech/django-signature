django-signature
================

Application to generate x509 certificates and sign models

Alpha : not really for production use

Features :
----------

 - Generate (or load) RSA keys and store them in Django models
 - Generate (or load) x509 certificates and store them in Django models
 - Generate (or load) x509 Requests and store them in Django models
 - Generate self-signed x509 for root CA
 - Sign Requests
 - Sign/verify text
 - Sign/verify simple models
 - Support FileField (with sha512 digest)

Todo :
------

 - Sign complex models
 - use RSA _OR_ EVP for Key's Models
 - More x509 attributes
 - ... and much more

Examples :
----------

There is an simple PKI example::

    from signature.models import Key, Certificate, Request
    from datetime import datetime

    before = datetime(2010, 01, 01)
    after = datetime(2015, 01, 01)
    ca_pwd = "R00tz"
    c_pwd = "1234"

    # CA and Client keys
    ca_key = Key.generate(ca_pwd)
    c_key = Key.generate(c_pwd)

    # CA Cert
    ca_cert = Certificate()
    ca_cert.CN = "Admin"
    ca_cert.C = "FR"
    ca_cert.key = ca_key
    ca_cert.begin = before
    ca_cert.end = after
    ca_cert.is_ca = True
    ca_cert.generate_x509_root(ca_pwd)

    # Client's request
    rqst = Request()
    rqst.CN = "World Company"
    rqst.C = "FR"
    rqst.key = c_key
    rqst.sign_request(c_pwd)

    # Sign client's request and return certificate
    c_cert = ca_cert.sign_request(rqst, before, after, ca_pwd)

For more examples, see SignaturePKITestCase into tests/test_project/apps/testapp/tests.py

There is an simple signature example::

    # Sign Text
    text = "This is a data"
    data_signed = c_cert.sign_text(text, c_pwd)
    result = c_cert.verify_smime(data_signed)

    # Sign Model (get text)
    auth1 = Author(name="Raymond E. Feist", title="MR")
    data_signed = c_cert.sign_model(auth1, c_pwd)
    result = c_cert.verify_smime(data_signed)

    # Sign Model (get Signature)
    auth1 = Author(name="Raymond E. Feist", title="MR")
    signed = c_cert.make_signature(auth1, self.c_pwd)
    signed.check_pkcs7(signed)

For more examples, see SignatureTestCase into tests/test_project/apps/testapp/tests.py

Tests :
-------

 - cd tests
 - python bootstrap.py
 - ./bin/buildout.py -v
 - ./bin/test-1.2 or ./bin/test-1.1

Requirements :
--------------

 - M2Crypto : http://chandlerproject.org/Projects/MeTooCrypto
 - Django >= 1.1
  