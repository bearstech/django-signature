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
        CA_pwd = "toto"
        user_pwd = "tata"

        # Generate CA's private key
        #
        t = NamedTemporaryFile()
        # We don't use tempfile for stdout because we want a variable
        # private_key for django_storage
        private_key = getoutput("openssl genrsa 4096")
        t.write(private_key)
        t.seek(0)
        print private_key

        # Generate Self signed RootCA
        #
        # TODO : generate and use temp openssl.cnf file
        #
        # Pipe pwd
        pCA_pwd = TemporaryFile()
        pCA_pwd.write(CA_pwd)
        pCA_pwd.seek(0)
        # Keep private key open while generating selfsigned certificate
        root_CA = getoutput("openssl req -new -x509 -batch -passout stdin -key %s" % t.name, stdin=pCA_pwd)
        print root_CA

        # Generate user private key
        #
        t2 = NamedTemporaryFile()
        # We don't use tempfile for stdout because we want a variable
        # private_key for django_storage
        user_private_key = getoutput("openssl genrsa 4096")
        t2.write(private_key)
        t2.seek(0)
        print user_private_key

        # Generate Sign request
        #
        # TODO : generate and use temp openssl.cnf file
        #
        # Pipe pwd
        puser_pwd = TemporaryFile()
        puser_pwd.write(CA_pwd)
        puser_pwd.seek(0)
        # Keep private key open while generating selfsigned certificate
        rqst = getoutput("openssl req -new -batch -passout stdin -key %s" % t2.name, stdin=puser_pwd)
        print rqst

        # Sign request
        #
        # TODO : generate and use temp openssl.cnf file
        #
        # Keep private key open while generating selfsigned certificate
        # t3 = request
        # t4 = root_CA
        # t = CA privkey
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
        print "OK"
        certificate = getoutput("openssl x509 -req -days 60 -passin stdin -in %s -CA %s -CAkey %s -CAserial %s -text" % (t3.name, t4.name, t.name, s.name), stdin=pCA_pwd)
        print certificate
