from django.test import TestCase
from django.contrib.auth.models import User
from django.conf import settings
from django.http import HttpRequest, QueryDict
from datetime import date

from subprocess import Popen, PIPE
import shlex

from tempfile import NamedTemporaryFile, TemporaryFile

def getoutput(cmd, stdin=PIPE):
    cmd = shlex.split(cmd)
    a =  Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=stdin).communicate()
    print a[1]
    return a[0]

class RawTestCase(TestCase):
    def testCertificateGeneration(self):
        """Test SSL certificate generation
        """
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
        # XXX : FAIL !!!
