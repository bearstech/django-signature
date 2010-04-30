from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.contrib.auth.models import User

class Certificate(models.Model):
    """An x509 certificate
    """
    user = models.ForeignKey(User)
    certificate = models.TextField()


class Key(models.Model):
    """An Private/public key pair
    """
    user = models.ForeignKey(User)

class Signature(models.Model):
    """A PKCS#7 signature for a model
    """
    object_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType)
    content_object = generic.GenericForeignKey('content_type', 'object_id')


