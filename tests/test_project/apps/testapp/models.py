from django.db import models
from django.utils.translation import ugettext_lazy as _

class Author(models.Model):
    TITLE_CHOICES = (
            ('MR', _('Mr.')),
            ('MRS', _('Mrs.')),
            ('MS', _('Ms.')),
    )
    name = models.CharField(_('Name'), max_length=100, default="Platon", unique=True)
    title = models.CharField(max_length=3, choices=TITLE_CHOICES)
    birth_date = models.DateField(blank=True, null=True)

    def __unicode__(self):
        return self.name

    def natural_key(self):
        return (self.name,)


class Whatamess(models.Model):
    TITLE_CHOICES = (
            (1, _('Mr.')),
            (2, _('Mrs.')),
            (3, _('Ms.')),
    )
    name = models.CharField(max_length=100)
    number = models.IntegerField()
    slug = models.SlugField()
    text = models.TextField()
    author = models.ForeignKey(Author, null=True)
    title = models.PositiveSmallIntegerField(max_length=3, choices=TITLE_CHOICES)
    birth_date = models.DateTimeField(blank=True, null=True)
    yesno = models.BooleanField()

    def __unicode__(self):
        return self.name

    def yes(self):
        return True

class AuthorProxy(Author):
        class Meta:
            proxy = True

        @property
        def aprint(self):
            return "I'm a proxy : %s" % self.name

class Book(models.Model):
    name = models.CharField(_('Name'), max_length=100, default="The Hitchhiker's Guide to the Galaxy", unique=True)
    afile = models.FileField(upload_to=".")
    #apicture = models.ImageField(upload_to="/", blank=True, null=True)

    def __unicode__(self):
        return self.name

    def natural_key(self):
        return (self.name,)
