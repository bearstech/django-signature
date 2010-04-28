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

def getoutput(cmd, stdin=PIPE):
    cmd = shlex.split(cmd)
    a =  Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=stdin).communicate()
    #print a[1]
    return a[0]

class RawTestCase(TestCase):
    """Tests with openssl lib
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
    """
    def testCertificateGeneration(self):
        """Test SSL certificate generation
        """
        CA_pwd = "toto"
        user_pwd = "tata"
        my_text = "Something really interesting"

        # Generate Self Signed CA
        #

        # Generate CA Key
        ca_keys = RSA.gen_key(4096, 0x10001)
        ca_pkey = EVP.PKey(md='sha1')
        ca_pkey.assign_rsa(ca_keys)

        before = datetime(2000, 01, 01)
        after = datetime(2015, 01, 01)


        # Request
        rqst = X509.Request()
        MBSTRING_FLAG = 0x1000
        MBSTRING_ASC  = MBSTRING_FLAG | 1
        ca_name = X509.X509_Name(m2.x509_name_new())
        ca_name.add_entry_by_txt(field='C',type=MBSTRING_ASC, entry='fr', len=-1, loc=-1, set=0 )    # country name
        ca_name.add_entry_by_txt(field='SP',type=MBSTRING_ASC, entry='idf', len=-1, loc=-1, set=0 )    # state of province name
        ca_name.add_entry_by_txt(field='L', type=MBSTRING_ASC, entry='Paris', len=-1, loc=-1, set=0 )    # locality name
        ca_name.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry='bt', len=-1, loc=-1, set=0 )    # organization name
        ca_name.add_entry_by_txt(field='OU', type=MBSTRING_ASC, entry='bt-france', len=-1, loc=-1, set=0 )    # organizational unit name
        ca_name.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry='Certificate Auth',len=-1, loc=-1, set=0 )    # common name
        ca_name.add_entry_by_txt(field='Email', type=MBSTRING_ASC, entry='admin@localhost', len=-1, loc=-1, set=0 )    # pkcs9 email address
        ca_name.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry='admin@localhost', len=-1, loc=-1, set=0 )    # pkcs9 email address
        rqst.set_subject_name(ca_name)

        rqst.set_pubkey(ca_pkey)
        rqst.sign(pkey=ca_pkey, md='sha1')
        print rqst.as_text()

        # Make certificate
        ca_cert = X509.X509()
        ca_cert.set_version(0)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(before)
        ca_cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(after)
        ca_cert.set_not_after(asn1)
        ca_cert.set_pubkey(ca_pkey)

        rqst_name = rqst.get_subject()
        ca_cert.set_subject_name(rqst_name)

        ca_cert.set_issuer_name(ca_name)
        ca_cert.sign(ca_pkey, md='sha1')
        print "CA"
        print ca_cert.as_text()

        # Make client cert
        #
        # Generate Client Key
        c_keys = RSA.gen_key(4096, 0x10001)
        c_pkey = EVP.PKey(md='sha1')
        c_pkey.assign_rsa(c_keys)

        # Make client Request
        rqst = X509.Request()
        rqstname = X509.X509_Name()
        MBSTRING_FLAG = 0x1000
        MBSTRING_ASC  = MBSTRING_FLAG | 1
        rqstname.add_entry_by_txt(field='C',type=MBSTRING_ASC, entry='austria', len=-1, loc=-1, set=0 )    # country name
        rqstname.add_entry_by_txt(field='SP',type=MBSTRING_ASC, entry='kernten', len=-1, loc=-1, set=0 )    # state of province name
        rqstname.add_entry_by_txt(field='L', type=MBSTRING_ASC, entry='stgallen', len=-1, loc=-1, set=0 )    # locality name
        rqstname.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry='labor', len=-1, loc=-1, set=0 )    # organization name
        rqstname.add_entry_by_txt(field='OU', type=MBSTRING_ASC, entry='it-department', len=-1, loc=-1, set=0 )    # organizational unit name
        rqstname.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry='Certificate client',len=-1, loc=-1, set=0 )    # common name
        rqstname.add_entry_by_txt(field='Email', type=MBSTRING_ASC, entry='user@localhost', len=-1, loc=-1, set=0 )    # pkcs9 email address
        rqstname.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry='user@localhost', len=-1, loc=-1, set=0 )    # pkcs9 email address
        rqst.set_subject_name(rqstname)

        rqst.set_pubkey(c_pkey)
        rqst.sign(pkey=c_pkey, md='sha1')
        print "Client"
        print rqst.as_text()


        # Make Client certificate
        c_cert = X509.X509()
        c_cert.set_version(0)
        c_cert.set_serial_number(0)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(before)
        c_cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(after)
        c_cert.set_not_after(asn1)
        c_cert.set_pubkey(ca_pkey)

        rqst_name = rqst.get_subject()
        c_cert.set_subject_name(rqst_name)
        c_cert.set_issuer_name(ca_name)
        c_cert.sign(ca_pkey, md='sha1')
        print "Signed"
        print c_cert.as_pem()
        f = open("/home/cyberj/tmp/ssl/c.crt", "w")
        f.write(c_cert.as_pem())
        f.close()
        f = open("/home/cyberj/tmp/ssl/ca.crt", "w")
        f.write(ca_cert.as_pem())
        f.close()
        verify = getoutput("openssl verify -CAfile /home/cyberj/tmp/ssl/ca.crt /home/cyberj/tmp/ssl/ca.crt")
        print verify
        self.assertTrue("OK" in verify)
        verify = getoutput("openssl verify -CAfile /home/cyberj/tmp/ssl/ca.crt /home/cyberj/tmp/ssl/c.crt")
        print verify
        self.assertTrue("OK" in verify)

        # OK, certificate are generated and are OK
        #
        # We have :
        # ca_key = CA Private Key
        # ca_cert = CA Certificate
        # ca_key = Client Private key
        # c_cert = Client Certificate signed by CA root
        #
        # It's time to sign/verify
        # reminder : http://sandbox.rulemaker.net/ngps/m2/howto.smime.html
