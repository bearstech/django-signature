# -*- coding: utf-8 -*-
from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.conf import settings
from django.core.files.base import File
from django.http import HttpRequest, QueryDict
from django.utils.encoding import smart_str

from subprocess import Popen, PIPE
from datetime import date
from M2Crypto import m2, ASN1, RSA, EVP, X509, BIO, SMIME
from datetime import datetime
from tempfile import NamedTemporaryFile, TemporaryFile

from signature.models import Key, Certificate, CertificateRequest, Signature
from signature.openssl import Openssl
from certificates import C_KEY, CA_KEY ,C_PUB_KEY, CA_CERT, C_REQUEST, C_CERT, U_CERT, U_KEY, U_REQUEST, UTF8_CERT
from certificates import C_KEY_PATH, CA_KEY_PATH, C_PUB_KEY_PATH, CA_CERT_PATH, C_REQUEST_PATH, C_CERT_PATH, U_CERT_PATH, U_KEY_PATH, U_REQUEST_PATH, UTF8_CERT_PATH

from models import Author, Whatamess, Book

import os
import shlex

class SignaturePKITestCase(TestCase):
    """Tests with django Signature + M2Cryto
    """
    def testKeyGenerationPrivate(self):
        """Test Private Key pair generation
        """
        user_pwd = "tata"
        k = Key.generate(user_pwd)
        k.save()
        self.assertTrue("-----BEGIN RSA PRIVATE KEY-----" in k.private)
        self.assertTrue("ENCRYPTED" in k.private)
        self.assertTrue("-----BEGIN PUBLIC KEY-----" in k.public)
        pkey = k.m2_pkey(user_pwd)
        self.assertTrue(isinstance(pkey, EVP.PKey))

    def testKeyGenerationPrivateUtf8(self):
        """Test Key pair generation with utf8 encoded password
        """
        password = "ééééèèèèçççùùù"
        k = Key.generate(password)
        k.save()
        k = Key.objects.get(id=k.id)
        self.assertTrue("-----BEGIN RSA PRIVATE KEY-----" in k.private)
        self.assertTrue("ENCRYPTED" in k.private)
        self.assertTrue("-----BEGIN PUBLIC KEY-----" in k.public)
        pkey = k.m2_pkey(password)
        self.assertTrue(isinstance(pkey, EVP.PKey))

    def testKeyGeneration(self):
        """Test Key pair generation without encryption
        """
        k = Key.generate(None)
        k.save()
        self.assertTrue("-----BEGIN RSA PRIVATE KEY-----" in k.private)
        self.assertTrue("ENCRYPTED" not in k.private)
        self.assertTrue("-----BEGIN PUBLIC KEY-----" in k.public)
        pkey = k.m2_pkey()
        self.assertTrue(isinstance(pkey, EVP.PKey))

    def testKeyLoading(self):
        """Try to load key
        """
        k = Key.new_from_pem(C_KEY, "1234")
        self.assertEqual(k.length, 4096)
        self.assertEqual(k.public, C_PUB_KEY)

    def testSelfCertificateGeneration(self):
        """With a Key, try to generate a self-signed certificate
        """
        before = datetime(2010, 01, 01)
        after = datetime(2015, 01, 01)
        user_pwd = "tata"
        key = Key.generate(user_pwd)
        key.save()
        cert = Certificate()
        cert.CN = "My CN"
        cert.country = "FR"
        cert.key = key
        cert.days = 300
        cert.is_ca = True
        cert.generate_x509_root(user_pwd)
        cert.save()
        cert_pem = cert.pem
        #self.assertEqual(cert.serial, 0)
        self.assertEqual(cert.ca_serial, 1)
        self.assertTrue(cert.is_ca)
        self.assertTrue(cert.trust)

        # Just test Certificate.m2_x509() method
        x509 = X509.load_cert_string(cert_pem, X509.FORMAT_PEM)
        m2x509 = cert.m2_x509()
        self.assertTrue(x509.as_text() == m2x509.as_text())

        self.assertTrue("CA:TRUE" in m2x509.as_text())
        self.assertTrue("Issuer: CN=My CN, C=FR" in m2x509.as_text())
        self.assertTrue("Subject: CN=My CN, C=FR" in m2x509.as_text())
        self.assertTrue("X509v3 Authority Key Identifier" in m2x509.as_text())
        self.assertTrue("X509v3 Subject Key Identifier" in m2x509.as_text())
        return cert_pem

    def testCertificateLoading(self):
        """Load x509 certificate
        """
        #before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        #after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
        x509_text = X509.load_cert_string(CA_CERT, X509.FORMAT_PEM).as_text()

        cert = Certificate.new_from_pem(CA_CERT)
        cert.save()
        self.assertTrue(cert.CN == "Admin")
        self.assertTrue(cert.country == "FR")
        #self.assertTrue(cert.begin == before)
        #self.assertTrue(cert.end == after)
        self.assertTrue(cert.is_ca)
        self.assertTrue(cert.auth_kid)
        self.assertTrue(cert.subject_kid)
        self.assertTrue(cert.certhash)
        self.assertTrue(" " not in cert.auth_kid)
        self.assertTrue(" " not in cert.subject_kid)
        # Just test Certificate.m2_x509() method
        x509 = X509.load_cert_string(cert.pem, X509.FORMAT_PEM)
        m2x509 = cert.m2_x509()
        self.assertTrue(x509.as_text() == m2x509.as_text())

        self.assertTrue(cert.auth_kid in m2x509.as_text())
        self.assertTrue(cert.subject_kid in m2x509.as_text())

    def testCertificateLoadingUTF8(self):
        """Load x509 certificate UTF8
        """
        #before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        #after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
        cert = Certificate.new_from_pem(UTF8_CERT)
        cert.save()
        self.assertEqual(cert.CN, u"Admin ©")
        self.assertEqual(cert.country, u"FR")
        cert = Certificate.objects.get(id=cert.id)
        self.assertEqual(cert.CN, u"Admin ©")
        self.assertEqual(cert.country, u"FR")

    def testRequestGeneration(self):
        """With a Key, try to generate a request
        """
        user_pwd = "tata"
        key = Key.generate(user_pwd)
        key.save()
        rqst = CertificateRequest()
        rqst.CN = "World Company"
        rqst.country = "FR"
        rqst.key = key
        rqst.sign_request(user_pwd)
        rqst.save()
        rqst_pem = rqst.pem

        m2rqst = rqst.m2_request()
        self.assertTrue("Subject: CN=World Company, C=FR" in m2rqst.as_text())
        return rqst_pem

    def testRequestLoading(self):
        """Load Request loading
        """
        m2rqst_text = X509.load_request_string(C_REQUEST, X509.FORMAT_PEM).as_text()

        rqst = CertificateRequest.new_from_pem(C_REQUEST)
        rqst.save()
        self.assertTrue(rqst.CN == "World Company")
        self.assertTrue(rqst.country == "FR")
        rqst_text = X509.load_request_string(rqst.pem, X509.FORMAT_PEM).as_text()
        self.assertTrue(rqst_text == m2rqst_text)

    def testSignaturePKI(self):
        """
        Symbol © is for testing utf8
        """
        before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
        ca_pwd = "R00tz"
        c_pwd = "1234"

        # CA and Client keys
        ca_key = Key.generate(ca_pwd)
        #print "\nCA PRIVATE\n", ca_key.private, "\n"
        c_key = Key.generate(c_pwd)
        #print "\nC PRIVATE\n", c_key.private, "\n"
        #print "\nC PUB\n", c_key.public, "\n"

        # CA Cert
        ca_cert = Certificate()
        ca_cert.CN = "Admin ©"
        ca_cert.country = "FR"
        ca_cert.key = ca_key
        ca_cert.begin = before
        ca_cert.end = after
        ca_cert.is_ca = True
        ca_cert.generate_x509_root(ca_pwd)
        ca_cert.save()
        self.assertEqual(ca_cert.ca_serial, 1)
        #print "\nCA cert\n", ca_cert.pem, "\n"

        # Client's request
        rqst = CertificateRequest()
        rqst.CN = "World Company ©"
        rqst.country = "FR"
        rqst.key = c_key
        rqst.sign_request(c_pwd)
        rqst.save()
        #print "\nRQST\n", rqst.pem, "\n"

        c_cert = ca_cert.sign_request(rqst, 300, ca_pwd)
        c_cert.save()
        #print "\nC_CERT\n", c_cert.pem, "\n"
        self.assertEqual(c_cert.serial, '2')
        self.assertEqual(ca_cert.ca_serial, 2)
        self.assertTrue("Signature ok" not in c_cert.pem)
        self.assertFalse(c_cert.trust)
        self.assertTrue(ca_cert.trust)
        self.assertTrue(ca_cert.certhash)
        self.assertTrue(c_cert.certhash)

        c_cert = Certificate.objects.get(id=c_cert.id)
        x509 = X509.load_cert_string(smart_str(c_cert.pem), X509.FORMAT_PEM)
        m2x509 = c_cert.m2_x509()
        self.assertTrue(x509.as_text() == m2x509.as_text())

        self.assertTrue("Issuer: CN=Admin \\xC2\\xA9, C=FR" in m2x509.as_text())
        self.assertTrue("Subject: CN=World Company \\xC2\\xA9, C=FR" in m2x509.as_text())
        self.assertTrue("X509v3 Authority Key Identifier" in m2x509.as_text())
        self.assertTrue("X509v3 Subject Key Identifier" in m2x509.as_text())

    def testSignaturePKIRevoke(self):
        """Try create - revoke - renew
        """
        before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
        ca_pwd = "R00tz"
        c_pwd = "1234"

        # CA and Client keys
        ca_key = Key.generate(ca_pwd)
        ca_key.save()
        #print "\nCA PRIVATE\n", ca_key.private, "\n"
        c_key = Key.generate(c_pwd)
        c_key.save()
        cc_key = Key.generate(c_pwd)
        cc_key.save()
        #print "\nC PRIVATE\n", c_key.private, "\n"
        #print "\nC PUB\n", c_key.public, "\n"

        # CA Cert
        ca_cert = Certificate()
        ca_cert.CN = "Admin"
        ca_cert.country = "FR"
        ca_cert.key = ca_key
        ca_cert.begin = before
        ca_cert.end = after
        ca_cert.is_ca = True
        ca_cert.generate_x509_root(ca_pwd)
        ca_cert.save()
        #print "\nCA cert\n", ca_cert.pem, "\n"

        # Client's request
        rqst = CertificateRequest()
        rqst.CN = "World Company ©"
        rqst.country = "FR"
        rqst.locality = "World"
        rqst.organization = "Company"
        rqst.OU = "Unknown"
        rqst.state = "Dummy"
        rqst.country = "FR"
        rqst.email = "dummy@dummy.fr"
        rqst.key = c_key
        rqst.sign_request(c_pwd)
        rqst.save()
        #print "\nRQST\n", rqst.pem, "\n"

        c_cert = ca_cert.sign_request(rqst, 300, ca_pwd)
        c_cert.save()
        #print "\nC_CERT\n", c_cert.pem, "\n"
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c_cert = Certificate.objects.get(pk=c_cert.id)
        ca_cert.revoke(c_cert, ca_pwd)
        ca_cert.save()
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c_cert = Certificate.objects.get(pk=c_cert.id)

        rqst.delete()
        # Client's new request
        rqst = CertificateRequest()
        rqst.CN = "World Company ©"
        rqst.country = "FR"
        rqst.locality = "World"
        rqst.organization = "Company"
        rqst.OU = "Unknown"
        rqst.state = "Dummy"
        rqst.country = "FR"
        rqst.email = "dummy@dummy.fr"
        rqst.key = c_key
        rqst.sign_request(c_pwd)
        rqst.save()
        #print "\nRQST\n", rqst.pem, "\n"
        c2_cert = ca_cert.sign_request(rqst, 300, ca_pwd)
        c2_cert.save()
        # Revoke new
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c2_cert = Certificate.objects.get(pk=c2_cert.id)
        ca_cert.revoke(c2_cert, ca_pwd)
        ca_cert.save()
        self.assertFalse(c2_cert.check())
        #print ca_cert.index
        #print [ca_cert.index]
        #print ca_cert.crl

        # Try another client
        rqst2 = CertificateRequest()
        rqst2.CN = "Country Company ©"
        rqst2.country = "FR"
        rqst2.locality = "Country"
        rqst2.organization = "Company"
        rqst2.OU = "Unknown"
        rqst2.state = "Dummy"
        rqst2.country = "FR"
        rqst2.email = "dummy2@dummy2.fr"
        rqst2.key = c_key
        rqst2.sign_request(c_pwd)
        rqst2.save()
        #print "\nRQST\n", rqst.pem, "\n"
        cc_cert = ca_cert.sign_request(rqst2, 300, ca_pwd)
        cc_cert.save()
        self.assertTrue(cc_cert.check())
        # Revoke new
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        cc_cert = Certificate.objects.get(pk=cc_cert.id)
        ca_cert.revoke(cc_cert, ca_pwd)
        ca_cert.save()
        self.assertFalse(cc_cert.check())
        #print ca_cert.index
        #print [ca_cert.index]
        #print ca_cert.crl


    def testSignaturePKIca(self):
        """Client certificate is a CA
        """
        # Turn this to True to regenerate examples certificates
        save = False

        before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
        ca_pwd = "R00tz"
        c_pwd = "1234"
        #c2_pwd = "abcd"

        # CA and Client keys
        ca_key = Key.generate(ca_pwd)
        c_key = Key.generate(c_pwd)
        c2_key = Key.generate(None)

        # CA Cert
        ca_cert = Certificate()
        ca_cert.CN = "Admin"
        ca_cert.country = "FR"
        ca_cert.key = ca_key
        ca_cert.days = 3000
        ca_cert.is_ca = True
        ca_cert.generate_x509_root(ca_pwd)

        # Client's request
        rqst = CertificateRequest()
        rqst.CN = "World Company"
        rqst.country = "FR"
        rqst.key = c_key
        rqst.sign_request(c_pwd)

        c_cert = ca_cert.sign_request(rqst, 200, ca_pwd, ca=True)
        self.assertEqual(c_cert.serial, '2')
        self.assertEqual(ca_cert.ca_serial, 2)

        # Just test Certificate.m2_x509() method
        x509 = X509.load_cert_string(c_cert.pem, X509.FORMAT_PEM)
        m2x509 = c_cert.m2_x509()
        self.assertTrue(x509.as_text() == m2x509.as_text())

        self.assertTrue("CA:TRUE" in m2x509.as_text())
        self.assertTrue("Issuer: CN=Admin, C=FR" in m2x509.as_text())
        self.assertTrue("Subject: CN=World Company, C=FR" in m2x509.as_text())
        self.assertTrue("X509v3 Authority Key Identifier" in m2x509.as_text())
        self.assertTrue("X509v3 Subject Key Identifier" in m2x509.as_text())
        self.assertTrue(c_cert.auth_kid)
        self.assertTrue(c_cert.subject_kid)
        self.assertTrue(" " not in c_cert.auth_kid)
        self.assertTrue(" " not in c_cert.subject_kid)
        self.assertTrue(c_cert.auth_kid in m2x509.as_text())
        self.assertTrue(c_cert.subject_kid in m2x509.as_text())
        # get authkey


        # Client's request
        urqst = CertificateRequest()
        urqst.CN = "Country Company"
        urqst.country = "FR"
        urqst.key = c2_key
        urqst.sign_request()

        c2_cert = c_cert.sign_request(urqst, 150, c_pwd)
        self.assertEqual(c2_cert.serial, '2')
        self.assertEqual(c_cert.ca_serial, 2)

        # Just test Certificate.m2_x509() method
        x509 = X509.load_cert_string(c2_cert.pem, X509.FORMAT_PEM)
        m2x509 = c2_cert.m2_x509()
        self.assertTrue(x509.as_text() == m2x509.as_text())

        self.assertTrue("Issuer: CN=World Company, C=FR" in m2x509.as_text())
        self.assertTrue("Subject: CN=Country Company, C=FR" in m2x509.as_text())
        self.assertTrue("X509v3 Authority Key Identifier" in m2x509.as_text())
        self.assertTrue("X509v3 Subject Key Identifier" in m2x509.as_text())
        self.assertTrue(c2_cert.auth_kid)
        self.assertTrue(c2_cert.subject_kid)
        self.assertTrue(c2_cert.auth_kid in m2x509.as_text())
        self.assertTrue(c2_cert.subject_kid in m2x509.as_text())
        self.assertTrue(" " not in c2_cert.auth_kid)
        self.assertTrue(" " not in c2_cert.subject_kid)

        # If all tests are goods, lets save it if needed
        if save:
            # UTF8 CA Cert
            utf8_key = Key.generate(ca_pwd)
            utf8_cert = Certificate()
            utf8_cert.CN = "Admin ©"
            utf8_cert.country = "FR"
            utf8_cert.key = utf8_key
            utf8_cert.begin = before
            utf8_cert.end = after
            utf8_cert.is_ca = True
            utf8_cert.generate_x509_root(ca_pwd)
            utf8_cert.save()
            open(CA_KEY_PATH, 'w').write(ca_key.private)
            open(C_KEY_PATH, 'w').write(c_key.private)
            open(U_KEY_PATH, 'w').write(c2_key.private)
            open(C_PUB_KEY_PATH, 'w').write(c_key.public)
            open(CA_CERT_PATH, 'w').write(ca_cert.pem)
            open(C_REQUEST_PATH, 'w').write(rqst.pem)
            open(C_CERT_PATH, 'w').write(c_cert.pem)
            open(U_CERT_PATH, 'w').write(c2_cert.pem)
            open(UTF8_CERT_PATH, 'w').write(utf8_cert.pem)
            print "SAVED"

    def testCertificateChainLoading(self):
        """Load many x509 and check relations
        """
        user = User(email="f@f.fr", username='toto')
        user.save()
        # Check relations for certs imports
        ca_key = Key.new_from_pem(CA_KEY, "R00tz")
        ca_key.user = user
        ca_key.save()
        ca_cert = Certificate.new_from_pem(CA_CERT)
        ca_cert.save()
        self.assertEqual(ca_cert.key, ca_key)

        # Check relations for keys imports
        c_cert = Certificate.new_from_pem(C_CERT)
        c_cert.save()
        c_key = Key.new_from_pem(C_KEY, "1234")
        # Refresh object
        c_cert = Certificate.objects.get(pk=c_cert.id)
        self.assertEqual(c_cert.key, c_key)

        # Check issuer relations
        u_cert = Certificate.new_from_pem(U_CERT)
        u_cert.save()
        u_key = Key.new_from_pem(U_KEY)
        self.assertTrue(u_cert.issuer == c_cert)
        self.assertTrue(u_cert.issuer.issuer == ca_cert)

    def testCertificateChainLoadingIssued(self):
        """Load many x509 and check _issued_ relations
        """
        user = User(email="f@f.fr", username='toto')
        user.save()
        # Check relations for certs imports
        ca_cert = Certificate.new_from_pem(CA_CERT)
        ca_cert.save()

        u_cert = Certificate.new_from_pem(U_CERT)
        u_cert.save()

        # Check relations for keys imports
        c_cert = Certificate.new_from_pem(C_CERT)
        c_cert.save()
        # Refresh object
        c_cert = Certificate.objects.get(pk=c_cert.id)
        u_cert = Certificate.objects.get(pk=u_cert.id)

        self.assertTrue(c_cert.issuer == ca_cert)
        self.assertTrue(u_cert.issuer == c_cert)

    def testCertificateCheck(self):
        """Load many x509 and check certificates
        """
        ca_pwd = "R00tz"
        c_pwd = "1234"
        # Check relations for certs imports
        ca_cert = Certificate.new_from_pem(CA_CERT)
        ca_cert.save()

        # Check relations for keys imports
        c_cert = Certificate.new_from_pem(C_CERT)
        c_cert.save()
        # Refresh object
        c_cert = Certificate.objects.get(pk=c_cert.id)

        # Check issuer relations
        u_cert = Certificate.new_from_pem(U_CERT)
        u_cert.save()

        self.assertEqual(c_cert.get_cert_chain(), [ca_cert, c_cert])
        self.assertEqual(u_cert.get_cert_chain(), [ca_cert, c_cert, u_cert])
        self.assertRaises(Openssl.VerifyError, ca_cert.check)
        self.assertRaises(Openssl.VerifyError, c_cert.check)
        self.assertRaises(Openssl.VerifyError, u_cert.check)
        ca_cert.trust = True
        ca_cert.save()

        # WTF ? we have to reload all objects after change ca_trust or
        # x_cert.get_cert_chain()[0].trust will be false
        # Tested with TransactionTestCase
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c_cert = Certificate.objects.get(pk=c_cert.id)
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertEqual(c_cert.get_cert_chain()[0].trust, True)

        self.assertTrue(ca_cert.check(crlcheck=False))
        self.assertTrue(c_cert.check(crlcheck=False))
        self.assertTrue(u_cert.check(crlcheck=False))

        # Add crl
        # Use Quick method
        c_cert.revoked = True
        c_cert.save()
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertFalse(u_cert.check(quick=True))
        c_cert.revoked = False
        c_cert.save()
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertTrue(u_cert.check())
        # Use openssl method
        c_cert.crl = "Wrong crl"
        c_cert.save()
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertRaises(Openssl.VerifyError, u_cert.check)
        # TODO : Add real CRL

        # Gen CRL for CA
        k = Key.new_from_pem(CA_KEY, ca_pwd)
        k.save()
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        ca_cert.ca_serial = 2
        ca_cert.save()
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        ca_cert.gen_crl(ca_pwd)
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        self.assertTrue("CRL" in ca_cert.crl)
        # Must works with this CRL
        c_cert.crl = None
        c_cert.save()
        u_cert = Certificate.objects.get(pk=u_cert.id)
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        self.assertTrue(u_cert.check())

        # Revoke client's certificate
        # Try with no crl
        ca_cert.crl = None
        ca_cert.save()
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        ca_cert.revoke(c_cert, ca_pwd)
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c_cert = Certificate.objects.get(pk=c_cert.id)
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertFalse(u_cert.check())
        c_cert.revoked = False
        c_cert.save()
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c_cert = Certificate.objects.get(pk=c_cert.id)
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertFalse(u_cert.check())
        self.assertTrue("02" in ca_cert.index)
        self.assertTrue("World Company" in ca_cert.index)

        # Revocation must be present on other crls
        ca_cert.gen_crl(ca_pwd)
        ca_cert = Certificate.objects.get(pk=ca_cert.id)
        c_cert = Certificate.objects.get(pk=c_cert.id)
        u_cert = Certificate.objects.get(pk=u_cert.id)
        self.assertFalse(u_cert.check())


class SignatureTestCase(TestCase):
    """Tests with django Signature + M2Cryto
    Sign some models
    """
    def setUp(self):
        """Load keys
        """
        self.ca_pwd = "R00tz"
        self.c_pwd = "1234"
        self.user_admin = User.objects.create(username="Admin", email="admin@server.bofh")
        self.user_client = User.objects.create(username="Client", email="client@internet.isp")
        ca_key = Key.new_from_pem(CA_KEY, "R00tz", self.user_admin)
        ca_key.save()
        c_key = Key.new_from_pem(C_KEY, "1234", self.user_client)
        c_key.save()
        ca_cert = Certificate.new_from_pem(CA_CERT, user=self.user_admin, key=ca_key)
        ca_cert.save()
        c_cert = Certificate.new_from_pem(C_CERT, user=self.user_client, key=c_key)
        c_cert.save()
        self.ca_key = Key.objects.get(id=ca_key.id)
        self.c_key = Key.objects.get(id=c_key.id)
        self.ca_cert = Certificate.objects.get(id=ca_cert.id)
        self.c_cert = Certificate.objects.get(id=c_cert.id)


    def testBasicTextPKCS7(self):
        """Try to sign a basic text
        """
        # Sign
        text = "This is a data"
        data_signed = self.c_cert.sign_text(text, self.c_pwd)
        result = self.c_cert.verify_smime(data_signed)
        self.assertTrue(result)
        self.assertEqual(result, text)

    def testBasicModelPKCS7(self):
        """Try to sign a basic model
        """
        # Sign
        auth1 = Author(name="Raymond E. Feist", title="MR")
        auth1.save()
        data_signed = self.c_cert.sign_model(auth1, self.c_pwd)
        result = self.c_cert.verify_smime(data_signed)
        self.assertTrue(result)

    def testComplexModelPKCS7(self):
        """Try to sign a complex model
        """
        # Sign
        auth1 = Author(name="Raymond E. Feist", title="MR")
        auth1.save()
        wam1 = Whatamess()
        wam1.name = "Woaw"
        wam1.number = 1
        wam1.slug = "woot"
        wam1.text= "This is a data"
        wam1.author = auth1
        wam1.title = 1
        wam1.birth_date = datetime.now()
        wam1.yesno = True
        wam1.save()
        data_signed = self.c_cert.sign_model(wam1, self.c_pwd)
        self.assertFalse("Raymond E. Feist" in data_signed)
        result = self.c_cert.verify_smime(data_signed)
        self.assertTrue(result)
        data_signed = self.c_cert.sign_model(wam1, self.c_pwd, use_natural_keys=True)
        self.assertTrue("Raymond E. Feist" in data_signed)
        result = self.c_cert.verify_smime(data_signed)
        self.assertTrue(result)

    def testBasicModelSignature(self):
        """Try to sign a basic model and get a Signature
        """
        # Sign
        auth1 = Author(name="Raymond E. Feist", title="MR")
        auth1.save()
        self.c_cert.save()
        signed = self.c_cert.make_signature(auth1, self.c_pwd)
        self.assertTrue(isinstance(signed, Signature))
        content_type = ContentType.objects.get_for_model(auth1)
        self.assertEqual(signed.content_type, content_type)
        self.assertEqual(signed.object_id, 1)
        signed.save()

        # Verify
        signed = Signature.objects.get(pk=1)
        result = signed.check_pkcs7()
        self.assertTrue(result)
        result = signed.check()
        self.assertTrue(result)
        auth1.name = "JR"
        auth1.save()
        signed = Signature.objects.get(pk=1)
        result = signed.check()
        self.assertFalse(result)

    def testFileModelSignature(self):
        """Try to sign a basic model and get a Signature
        """
        # Sign
        filepath = os.path.join(settings.MEDIA_ROOT, 'afile.txt')
        book1 = Book(name="A book", afile=filepath)
        book1.save()
        book1 = Book.objects.get(pk=1)
        signed = self.c_cert.make_signature(book1, self.c_pwd)
        self.assertTrue(isinstance(signed, Signature))
        content_type = ContentType.objects.get_for_model(book1)
        self.assertEqual(signed.content_type, content_type)
        self.assertEqual(signed.object_id, 1)
        signed.save()

        # Verify
        signed = Signature.objects.get(pk=1)
        result = signed.check_pkcs7()
        self.assertTrue(result)
        result = signed.check()
        self.assertTrue(result)

        # other file with same content
        filepath = os.path.join(settings.MEDIA_ROOT, 'otherfile.txt')
        book1.afile = filepath
        book1.save()
        signed = Signature.objects.get(pk=1)
        result = signed.check_pkcs7()
        self.assertTrue(result)
        result = signed.check()
        self.assertTrue(result)

        # other file with wrong content
        afile = "wrongfile.txt"
        filepath = os.path.join(settings.MEDIA_ROOT, 'wrongfile.txt')
        book1.afile = filepath
        book1.save()
        signed = Signature.objects.get(pk=1)
        result = signed.check()
        self.assertFalse(result)

##################################
# Following tests are just for
# Code practice with openssl
# or M2Crypto
# They will be deleted
##################################

def getoutput(cmd, stdin=PIPE):
    cmd = shlex.split(cmd)
    a =  Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=stdin).communicate()
    #print a[1]
    return a[0]


class RawTestCase(TestCase):
    """Tests with openssl lib

    Just for practice
    """
    def testCertificateGeneration(self):
        """Test SSL certificate generation
        """
        return
        # Pipe CA password
        CA_pwd = "toto"
        pCA_pwd = TemporaryFile()
        pCA_pwd.write(CA_pwd)
        pCA_pwd.seek(0)
        # Pipe User Password
        user_pwd = "tata"
        puser_pwd = TemporaryFile()
        puser_pwd.write(CA_pwd)
        puser_pwd.seek(0)

        # Generate CA's private key
        #
        # t = CA privkey
        t = NamedTemporaryFile()
        # We don't use tempfile for stdout because we want a variable
        # private_key for django_storage
        private_key = getoutput("openssl genrsa 4096")
        t.write(private_key)
        t.seek(0)

        # Generate Self signed RootCA
        #
        # TODO : generate and use temp openssl.cnf file
        #
        # Keep private key open while generating selfsigned certificate
        root_CA = getoutput("openssl req -new -x509 -batch -passout stdin -key %s" % t.name, stdin=pCA_pwd)

        # Generate user private key
        #
        # t2 = User private key
        t2 = NamedTemporaryFile()
        # We don't use tempfile for stdout because we want a variable
        # private_key for django_storage
        user_private_key = getoutput("openssl genrsa 4096")
        t2.write(private_key)
        t2.seek(0)

        # Generate Sign request
        #
        # TODO : generate and use temp openssl.cnf file
        #
        # t2 = User private key
        rqst = getoutput("openssl req -new -batch -passout stdin -key %s" % t2.name, stdin=puser_pwd)

        # Sign request
        #
        # TODO : 
        #   * generate and use temp openssl.cnf file
        #   * Verify informations
        #
        # Keep private key open while generating selfsigned certificate
        # t = CA privkey
        # t3 = request
        # t4 = root_CA
        # s = SerialFile
        t3 = NamedTemporaryFile()
        t3.write(rqst)
        t3.seek(0)
        t4 = NamedTemporaryFile()
        t4.write(root_CA)
        t4.seek(0)
        t.seek(0)
        pCA_pwd.seek(0)
        s = NamedTemporaryFile()
        s.write("02")
        s.seek(0)
        # subject = '/countryName=France/stateOrProvinceName=Ile-de-france/localityName=Paris/organizationName=Django-signature/organizationalUnitName=django-signature/commonName=iamauser'
        certificate = getoutput("openssl x509 -req -days 730 -passin stdin -in %s -CA %s -CAkey %s -CAserial %s" % (t3.name, t4.name, t.name, s.name), stdin=pCA_pwd)

        # Get public key from private key
        #
        # pcertificate = certificate
        # t2 = User private key
        t2.seek(0)
        pubkey = getoutput("openssl rsa -pubout -in %s" % t2.name)

        # Sign Something with certificate
        #
        # t2 = User private key
        pmy_text = NamedTemporaryFile()
        pmy_text.write(root_CA)
        pmy_text.seek(0)
        t2.seek(0)
        my_text = "Something really interesting"
        signature = getoutput("openssl dgst -sha1 -sign %s -hex -c" % (t2.name), stdin=pmy_text)

        # Verify text
        #
        # ppubkey = pubkey
        # XXX : FAIL !!!
        pmy_text.seek(0)
        psignature = NamedTemporaryFile()
        psignature.write(signature)
        psignature.seek(0)
        ppubkey = NamedTemporaryFile()
        ppubkey.write(pubkey)
        ppubkey.seek(0)
        verify = getoutput("openssl dgst -sha1 -verify %s -hex -signature %s" % (ppubkey.name, psignature.name), stdin=pmy_text)
        self.assertTrue("OK" in verify)
        # XXX : FAIL !!!

class M2TestCase(TestCase):
    """Tests with m2Crypto lib

    http://chandlerproject.org/bin/view/Projects/MeTooCrypto

    Theses tests are built with help of M2Crypto's testsuite
    """
    def quiet_callback(*args):
        return

    def testCertificateGeneration(self):
        """Test SSL certificate generation
        """
        CA_pwd = "toto"
        user_pwd = "tata"
        my_text = "Something really interesting"
        before = datetime(2000, 01, 01)
        after = datetime(2015, 01, 01)

        # Generate Self Signed CA #
        #
        # Generate CA Key
        ca_keys = RSA.gen_key(4096, 0x10001, callback=self.quiet_callback)
        ca_pkey = EVP.PKey(md='sha1')
        ca_pkey.assign_rsa(ca_keys)

        # Generate CA Request
        rqst = X509.Request()
        ca_name = rqst.get_subject()
        ca_name.C = "FR"
        ca_name.CN = "Certificate Auth"
        rqst.set_pubkey(ca_pkey)
        # Sign request
        rqst.sign(pkey=ca_pkey, md='sha1')
        #print rqst.as_text()

        # Make CA's self-signed certificate with CA request
        ca_cert = X509.X509()
        ca_cert.set_version(2)
        # Set certificate expiration
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(before)
        ca_cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(after)
        ca_cert.set_not_after(asn1)
        # Use CA pubkey
        ca_cert.set_pubkey(ca_pkey)
        # Self signed : subject = issuer
        ca_cert.set_subject_name(ca_name)
        ca_cert.set_issuer_name(ca_name)
        # Add CA Constraint
        ext = X509.new_extension('basicConstraints', 'CA:TRUE')
        ca_cert.add_ext(ext)
        # Sign CA with CA's privkey
        ca_cert.sign(ca_pkey, md='sha1')
        #print "CA"
        #print ca_cert.as_text()
        self.assertTrue(ca_cert.check_ca())

        # Make client Certificate #
        #
        # Generate Client Key
        c_keys = RSA.gen_key(4096, 0x10001, callback=self.quiet_callback)
        c_pkey = EVP.PKey(md='sha1')
        c_pkey.assign_rsa(c_keys)

        # Generate client Request
        rqst = X509.Request()
        rqst_name = rqst.get_subject()
        rqst_name.C = "FR"
        rqst_name.CN = "Client to Auth"
        rqst_name.O = "My Big Company"
        rqst.set_pubkey(c_pkey)
        rqst.set_subject_name(rqst_name)
        # Sign request
        rqst.sign(pkey=c_pkey, md='sha1')
        #print "Client"
        #print rqst.as_text()

        # Make Client certificate with CA's key
        c_cert = X509.X509()
        c_cert.set_version(2)
        c_cert.set_serial_number(0)
        # Set certificate expiration
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(before)
        c_cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(after)
        c_cert.set_not_after(asn1)
        # Get subject from request
        sub = rqst.get_subject()
        c_cert.set_subject(sub)
        # use client pubkey
        c_cert.set_pubkey(c_pkey)
        # issuer = CA
        ca_name = X509.X509_Name()
        ca_name.C = "FR"
        ca_name.CN = "Certificate Auth"
        c_cert.set_issuer(ca_name)
        # Sign Certificate with CA key
        c_cert.sign(ca_pkey, md='sha1')
        #print "Signed"
        #print c_cert.as_text()

        # Somes checks with openssl
        c_cert_temp = NamedTemporaryFile()
        ca_cert_temp = NamedTemporaryFile()
        c_cert.save_pem(c_cert_temp.name)
        ca_cert.save_pem(ca_cert_temp.name)
        # Verifiy CA with itself
        verify = getoutput("openssl verify -CAfile %s %s" % (ca_cert_temp.name, ca_cert_temp.name))
        #print verify
        self.assertTrue("OK" in verify)
        # Verifiy client cert with CA
        verify = getoutput("openssl verify -CAfile %s %s" % (ca_cert_temp.name, c_cert_temp.name))
        #print verify
        self.assertTrue("OK" in verify)
        #from M2Crypto.util import no_passphrase_callback
        #c_keys.save_key("/home/cyberj/tmp/ssl/c_pkey.pem", cipher=None, callback=no_passphrase_callback)
        #c_keys.save_key_bio(biog, cipher=None, callback=no_passphrase_callback)
        #ca_pkey.save_key("/home/cyberj/tmp/ssl/ca_pkey.pem", cipher=None, callback=no_passphrase_callback)

        # OK, certificate are generated and are OK
        #
        # We have :
        # ca_pkey = CA pub/Private Key
        # ca_cert = CA Certificate
        # c_pkey = Client pub/Private key
        # c_cert = Client Certificate signed by CA root
        #
        # It's time to sign/verify
        # reminder : http://sandbox.rulemaker.net/ngps/m2/howto.smime.html
        # reminder : http://svn.osafoundation.org/m2crypto/trunk/M2Crypto/SMIME.py

        from M2Crypto import BIO, SMIME
        text = "This is a data"
        # Set context
        s = SMIME.SMIME()
        s.pkey = c_pkey
        s.x509 = c_cert
        # Sign
        buf = BIO.MemoryBuffer(text)
        p7 = s.sign(buf, SMIME.PKCS7_DETACHED)
        # write content + signature
        out = BIO.MemoryBuffer()
        s.write(out, p7, BIO.MemoryBuffer(text))
        # get data signed
        data_signed = out.read()
        # data_signed is like : http://friendpaste.com/3fi7Ub8c2jYLxUR2f7wQ68
        # Save signed for tests
        #f = open("/home/cyberj/tmp/ssl/signed.mime", 'w')
        #f.write(data_signed)
        #f.close()

        # Check
        #print "Check"
        s = SMIME.SMIME()
        # Adds client crt
        sk = X509.X509_Stack()
        sk.push(c_cert)
        s.set_x509_stack(sk)
        # Adds CA crt
        st = X509.X509_Store()
        st.add_x509(ca_cert)
        s.set_x509_store(st)
        # Get data and p7 from data_signed
        bio_data_signed = BIO.MemoryBuffer(data_signed)
        p7, data = SMIME.smime_load_pkcs7_bio(bio_data_signed)
        #print data
        #print p7
        bio_data_wrong = BIO.MemoryBuffer("This is a duta")
        bio_data = BIO.MemoryBuffer("This is a data")
        verified = s.verify(p7, bio_data)
        #print verified
        self.assertRaises(SMIME.PKCS7_Error, s.verify, p7, bio_data_wrong)

