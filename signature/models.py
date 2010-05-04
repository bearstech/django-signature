from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509
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


class Certificate(models.Model):
    """An x509 certificate
    """
    STATE_REQUEST = 0
    STATE_SIGNED = 1
    STATE_CHOICES = (
        (STATE_REQUEST, _("Request")),
        (STATE_REQUEST, _("Signed")),
    )

    state = models.PositiveSmallIntegerField(choices=STATE_CHOICES, default=STATE_REQUEST)
    user = models.ForeignKey(User, null=True)
    key = models.ForeignKey(Key, null=True)
    pem = models.TextField(editable=False)
    C = models.CharField(max_length=2)
    CN = models.CharField(max_length=50)
    begin = models.DateTimeField()
    end = models.DateTimeField()
    is_ca = models.BooleanField(default=False)
    issuer = models.ForeignKey('self', related_name='issuer_set', null=True)

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
        if self.is_ca:
            # Add CA Constraint
            ext = X509.new_extension('basicConstraints', 'CA:TRUE')
            ca_cert.add_ext(ext)
            self.is_ca = True
        # Sign CA with CA's privkey
        ca_cert.sign(ca_pkey, md='sha1')
        self.pem = ca_cert.as_pem()

    @classmethod
    def new_from_pem(cls, pem, user=None):
        """Create a Certificate Instance with an existing PEM
        """
        cert = cls(user=user)
        x509 = X509.load_cert_string(pem, X509.FORMAT_PEM)
        cert.pem = x509.as_pem()
        issuer = x509.get_issuer()
        cert.C = issuer.C
        cert.CN = issuer.CN
        cert.begin = x509.get_not_before().get_datetime()
        cert.end = x509.get_not_after().get_datetime()
        if x509.check_ca():
            cert.is_ca = True
        return cert


class Signature(models.Model):
    """A PKCS#7 signature for a model
    """
    object_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType)
    content_object = generic.GenericForeignKey('content_type', 'object_id')


