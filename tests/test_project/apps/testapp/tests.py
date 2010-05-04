from django.test import TestCase
from django.contrib.auth.models import User
from django.conf import settings
from django.http import HttpRequest, QueryDict
from datetime import date

from subprocess import Popen, PIPE
import shlex
from M2Crypto import m2, ASN1, RSA, EVP, X509

from datetime import datetime

from tempfile import NamedTemporaryFile, TemporaryFile

from signature.models import Key, Certificate, Request
from certificates import C_KEY, CA_KEY ,C_PUB_KEY, CA_CERT, C_REQUEST, C_CERT


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

        #s.verify(p7, bio_data_wrong) # XXX : WTF Segfault ???

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
        self.assertTrue(k.length == 4096)
        self.assertTrue(k.public == C_PUB_KEY)

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
        cert.C = "FR"
        cert.key = key
        cert.begin = before
        cert.end = after
        cert.is_ca = True
        cert.generate_x509_root(user_pwd)
        cert.save()
        cert_pem = cert.pem

        # Just test Certificate.m2_x509() method
        x509 = X509.load_cert_string(cert_pem, X509.FORMAT_PEM)
        m2x509 = cert.m2_x509()
        self.assertTrue(x509.as_text() == m2x509.as_text())

        self.assertTrue("CA:TRUE" in m2x509.as_text())
        self.assertTrue("Issuer: C=FR, CN=My CN" in m2x509.as_text())
        self.assertTrue("Subject: C=FR, CN=My CN" in m2x509.as_text())
        return cert_pem

    def testCertificateLoading(self):
        """Load x509 certificate
        """
        before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
        x509_text = X509.load_cert_string(CA_CERT, X509.FORMAT_PEM).as_text()

        cert = Certificate.new_from_pem(CA_CERT)
        cert.save()
        self.assertTrue(cert.CN == "Admin")
        self.assertTrue(cert.C == "FR")
        self.assertTrue(cert.begin == before)
        self.assertTrue(cert.end == after)
        self.assertTrue(cert.is_ca)
        cert_text = X509.load_cert_string(cert.pem, X509.FORMAT_PEM).as_text()
        self.assertTrue(cert_text == x509_text)

    def testRequestGeneration(self):
        """With a Key, try to generate a request
        """
        user_pwd = "tata"
        key = Key.generate(user_pwd)
        key.save()
        rqst = Request()
        rqst.CN = "World Company"
        rqst.C = "FR"
        rqst.key = key
        rqst.generate_request(user_pwd)
        rqst.save()
        rqst_pem = rqst.pem

        m2rqst = rqst.m2_request()
        self.assertTrue("Subject: C=FR, CN=World Company" in m2rqst.as_text())
        return rqst_pem

    def testRequestLoading(self):
        """Load Request loading
        """
        m2rqst_text = X509.load_request_string(C_REQUEST, X509.FORMAT_PEM).as_text()

        rqst = Request.new_from_pem(C_REQUEST)
        rqst.save()
        self.assertTrue(rqst.CN == "World Company")
        self.assertTrue(rqst.C == "FR")
        rqst_text = X509.load_request_string(rqst.pem, X509.FORMAT_PEM).as_text()
        self.assertTrue(rqst_text == m2rqst_text)

    def testSignaturePKI(self):
        """
        """
        before = datetime(2010, 01, 01, 6, tzinfo=ASN1.UTC)
        after = datetime(2015, 01, 01, 6, tzinfo=ASN1.UTC)
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
        rqst.generate_request(c_pwd)

        c_cert = ca_cert.sign_request(rqst, before, after, ca_pwd)

class SignatureTestCase(TestCase):
    """Tests with django Signature + M2Cryto
    Sign some models
    """
    def setUp(self):
        """Load keys
        """
        self.user_admin = User.objects.create(username="Admin", email="admin@server.bofh")
        self.user_client = User.objects.create(username="Client", email="client@internet.isp")
        self.ca_key = Key.new_from_pem(CA_KEY, "R00tz", self.user_admin)
        self.c_key = Key.new_from_pem(C_KEY, "1234", self.user_client)
        self.ca_cert = Certificate.new_from_pem(CA_CERT, user=self.user_admin, key=self.ca_key)
        self.c_cert = Certificate.new_from_pem(C_CERT, user=self.user_client, key=self.c_key)

    def testBasicSignature(self):
        """Try to sign a basic object
        """
        pass
