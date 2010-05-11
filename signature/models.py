from django.db import models
from django.core import serializers
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509, SMIME
from M2Crypto.util import no_passphrase_callback

def quiet_callback(*args):
        return

def quiet_passphrase(passphrase=None):
    if passphrase == None:
        ciph = None
        cb = no_passphrase_callback
    else:
        ciph = 'aes_128_cbc'
        cb = lambda a: passphrase
    return ciph, cb

class Key(models.Model):
    """An Private/public key pair

    TODO : RSA/EVP ??
    """
    user = models.ForeignKey(User, null=True)
    length = models.PositiveIntegerField(editable=False)
    private = models.TextField(editable=False)
    public = models.TextField(editable=False)

    @classmethod
    def generate(cls, passphrase, length=4096, user=None):
        """Return an Key instance with RSA key generated
        """
        ciph, cb = quiet_passphrase(passphrase)
        keys = RSA.gen_key(length, 0x10001, callback=quiet_callback)
        key = cls()
        key.length = length
        bio = BIO.MemoryBuffer()
        keys.save_pub_key_bio(bio)
        key.public = bio.read()
        keys.save_key_bio(bio, cipher=ciph, callback=cb)
        key.private = bio.read()
        return key

    def m2_rsa(self, passphrase=None):
        """Return M2Crypto RSA's instance of key
        """
        ciph, cb = quiet_passphrase(passphrase)
        rsakeyp = RSA.load_key_string(self.private, cb)
        return rsakeyp

    def m2_pkey(self, passphrase=None):
        """Return M2Crypto EVP's instance of key
        """
        rsakeyp = self.m2_rsa(passphrase)
        ciph, cb = quiet_passphrase(passphrase)
        evp_pkey = EVP.PKey(md='sha1')
        evp_pkey.assign_rsa(rsakeyp)
        return evp_pkey

    @classmethod
    def new_from_pem(cls, pem, passphrase=None, user=None):
        """Create a Key Instance with an existing PEM
        """
        ciph, cb = quiet_passphrase(passphrase)
        key = cls(user=user)
        m2key = RSA.load_key_string(pem, cb)
        key.private = m2key.as_pem(ciph, cb)
        bio = BIO.MemoryBuffer()
        m2key.save_pub_key_bio(bio)
        key.public = bio.read()
        key.length = len(m2key)
        return key

class Request(models.Model):
    """A CSR
    """
    user = models.ForeignKey(User, null=True)
    key = models.ForeignKey(Key, null=True)
    pem = models.TextField(editable=False)
    C = models.CharField(max_length=2)
    CN = models.CharField(max_length=50)

    def m2_request(self):
        """Return M2Crypto's Request instance
        """
        rqst = X509.load_request_string(self.pem, X509.FORMAT_PEM)
        return rqst

    def sign_request(self, passphrase=None):
        """Generate request with instance informations
        """
        # TODO : class for C / CN and all attributes
        # Generate CA Request
        rqst = X509.Request()
        issuer_name = rqst.get_subject()
        issuer_name.C = self.C
        issuer_name.CN = self.CN
        issuer_pkey = self.key.m2_pkey(passphrase)
        rqst.set_pubkey(issuer_pkey)
        rqst.sign(pkey=issuer_pkey, md='sha1')
        self.pem = rqst.as_pem()

    @classmethod
    def new_from_pem(cls, pem, user=None, key=None):
        """Create a Request Instance with an existing PEM
        """
        rqst = cls(user=user, key=key)
        m2rqst = X509.load_request_string(pem, X509.FORMAT_PEM)
        rqst.pem = m2rqst.as_pem()
        subject = m2rqst.get_subject()
        rqst.C = subject.C
        rqst.CN = subject.CN
        return rqst

class Signature(models.Model):
    """A PKCS#7 signature for a model
    """
    certificate = models.ForeignKey('Certificate')
    object_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType)
    content_object = generic.GenericForeignKey('content_type', 'object_id')

class Certificate(models.Model):
    """An x509 certificate
    """
    user = models.ForeignKey(User, null=True)
    key = models.ForeignKey(Key, null=True)
    pem = models.TextField(editable=False)
    C = models.CharField(max_length=2)
    CN = models.CharField(max_length=50)
    begin = models.DateTimeField()
    end = models.DateTimeField()
    serial = models.PositiveIntegerField(editable=False)
    issuer = models.ForeignKey('self', related_name='issuer_set', null=True)
    is_ca = models.BooleanField(default=False)
    ca_serial = models.PositiveIntegerField(null=True, editable=False)

    def m2_x509(self):
        """Return M2Crypto's x509 instance of certificate
        """
        cert = X509.load_cert_string(self.pem, X509.FORMAT_PEM)
        return cert

    def generate_x509_root(self, passphrase=None):
        """Generate x509 certificate with instance informations
        """
        # TODO : class for C / CN and all attributes
        # Generate CA Request
        rqst = X509.Request()
        ca_name = rqst.get_subject()
        ca_name.C = self.C
        ca_name.CN = self.CN
        ca_pkey = self.key.m2_pkey(passphrase)

        rqst.set_pubkey(ca_pkey)
        # Sign request
        rqst.sign(pkey=ca_pkey, md='sha1')
        #print rqst.as_text()

        # Make CA's self-signed certificate with CA request
        ca_cert = X509.X509()
        #ca_cert.set_version(2)
        # Set certificate expiration
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(self.begin)
        ca_cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(self.end)
        ca_cert.set_not_after(asn1)
        # Use CA pubkey
        ca_cert.set_pubkey(ca_pkey)
        # Self signed : subject = issuer
        ca_cert.set_subject_name(ca_name)
        ca_cert.set_issuer_name(ca_name)
        self.serial = 0
        if self.is_ca:
            # Add CA Constraint
            ext = X509.new_extension('basicConstraints', 'CA:TRUE')
            ca_cert.add_ext(ext)
            self.is_ca = True
            self.ca_serial = 1
        # Sign CA with CA's privkey
        ca_cert.sign(ca_pkey, md='sha1')
        self.pem = ca_cert.as_pem()

    def sign_request(self, rqst, not_before, not_after, passphrase=None):
        """Sign a Request and return a Certificate instance
        """
        # TODO : class for C / CN and all attributes
        # Generate CA Request
        m2rqst = rqst.m2_request()
        c_name = m2rqst.get_subject()
        c_cert = Certificate()
        c_cert.C = c_name.C
        c_cert.CN = c_name.CN
        c_cert.end = not_after
        c_cert.begin = not_before
        c_cert.key = rqst.key
        c_cert.user = rqst.user
        c_cert.issuer = self
        ca_pkey = self.key.m2_pkey(passphrase)

        # Make CA's self-signed certificate with CA request
        m2_cert = X509.X509()
        m2_cert.set_version(2)
        m2_cert.set_serial_number(self.ca_serial)
        c_cert.serial = self.ca_serial
        self.ca_serial = self.ca_serial+1
        # Set certificate expiration
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(not_before)
        m2_cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_datetime(not_after)
        m2_cert.set_not_after(asn1)
        # Use CA pubkey
        m2_cert.set_pubkey(m2rqst.get_pubkey())
        # Issuer
        ca_name = X509.X509_Name()
        ca_name.C = self.C
        ca_name.CN = self.CN
        m2_cert.set_issuer_name(ca_name)
        # Subject
        m2_cert.set_subject_name(c_name)
        # Sign Cert with CA's privkey
        m2_cert.sign(ca_pkey, md='sha1')
        c_cert.pem = m2_cert.as_pem()

        # And return new instance
        return c_cert

    @classmethod
    def new_from_pem(cls, pem, user=None, key=None):
        """Create a Certificate Instance with an existing PEM
        """
        cert = cls(user=user, key=key)
        x509 = X509.load_cert_string(pem, X509.FORMAT_PEM)
        cert.pem = x509.as_pem()
        issuer = x509.get_issuer()
        cert.C = issuer.C
        cert.CN = issuer.CN
        cert.serial = x509.get_serial_number()
        cert.begin = x509.get_not_before().get_datetime()
        cert.end = x509.get_not_after().get_datetime()
        if x509.check_ca():
            cert.is_ca = True
        return cert

    def sign_text(self, text, passphrase):
        """Sign a text with cert's key and passphrase
        """
        if not self.key:
            raise Exception("No key for this certificate")

        # Set context
        s = SMIME.SMIME()
        s.x509 = self.m2_x509()
        s.pkey = self.key.m2_pkey(passphrase)
        #buf = BIO.MemoryBuffer()
        #xx, cb = quiet_passphrase()
        #self.key.m2_rsa(passphrase).save_key_bio(buf, callback=cb, cipher=xx)
        #print buf.read()
        # Sign
        buf = BIO.MemoryBuffer(text)
        p7 = s.sign(buf, SMIME.PKCS7_DETACHED)
        # write content + signature
        out = BIO.MemoryBuffer()
        s.write(out, p7, BIO.MemoryBuffer(text))
        # get data signed
        data_signed = out.read()
        return data_signed

    def sign_model(self, obj, passphrase):
        """Sign a model instance or a queryset
        """
        data = [obj]
        serialized = serializers.serialize('yaml', data)
        signed = self.sign_text(serialized, passphrase)
        return signed

    def verify_smime(self, smime):
        """Verify an smime signed message
        """
        # Check
        #print "Check"
        s = SMIME.SMIME()
        # Adds client crt
        sk = X509.X509_Stack()
        sk.push(self.m2_x509())
        s.set_x509_stack(sk)
        # Adds CA crt
        st = X509.X509_Store()
        st.add_cert(self.issuer.m2_x509())
        s.set_x509_store(st)

        # Get data and p7 from data_signed
        bio_smime = BIO.MemoryBuffer(smime)
        p7, data = SMIME.smime_load_pkcs7_bio(bio_smime)
        try:
            verified = s.verify(p7, data)
        except SMIME.PKCS7_Error:
            return False
        return True


    def sign_object(instance, passphrase, fields=[], exclude=[]):
        """Sign a Model instance with passphrase
        """
        if not self.key:
            raise Exception("No key for this certificate")

        content_type = ContentType.objects.get_for_model(instance)

        text = "This is a data"
        # Set context
        s = SMIME.SMIME()
        s.x509 = self.m2_x509()
        s.pkey = self.key.m2_evp()
        # Sign
        buf = BIO.MemoryBuffer(text)
        p7 = s.sign(buf, SMIME.PKCS7_DETACHED)
        # write content + signature
        out = BIO.MemoryBuffer()
        s.write(out, p7, BIO.MemoryBuffer(text))
        # get data signed
        data_signed = out.read()

