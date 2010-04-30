from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509
from M2Crypto.util import no_passphrase_callback

def quiet_callback(*args):
    return

def quiet_passphrase(*args):
    return

class Certificate(models.Model):
    """An x509 certificate
    """
    user = models.ForeignKey(User)
    certificate = models.TextField()


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
        keys = RSA.gen_key(length, 0x10001, callback=quiet_callback)
        key = cls()
        key.length = length
        bio = BIO.MemoryBuffer()
        keys.save_pub_key_bio(bio)
        key.public = bio.read()
        keys.save_key_bio(bio, cipher=None, callback=no_passphrase_callback)
        key.private = bio.read()
        return key


class Signature(models.Model):
    """A PKCS#7 signature for a model
    """
    object_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType)
    content_object = generic.GenericForeignKey('content_type', 'object_id')


