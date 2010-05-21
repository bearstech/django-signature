import datetime
from django import forms
from django.core.serializers.pyyaml import Serializer as DjangoYAMLEncoder
from django.core.serializers.pyyaml import DjangoSafeDumper
from django.core import serializers
from django.db import models
from django.forms import fields

from StringIO import StringIO

from django.db import models
from django.utils.encoding import smart_str, smart_unicode
from django.utils import datetime_safe

import yaml
from hashlib import sha512


# The code here is a copy of django/core/serializers source files
# With adjonctions for FileFields sha512

class SMIMESerializer(DjangoYAMLEncoder):
    """
    Serializer for signatures
    """
    def serialize(self, queryset, **options):
        """
        Serialize a queryset.
        """
        self.options = options

        self.stream = options.get("stream", StringIO())
        self.selected_fields = options.get("fields")
        self.use_natural_keys = options.get("use_natural_keys", False)

        self.start_serialization()
        for obj in queryset:
            self.start_object(obj)
            for field in obj._meta.local_fields:
                if field.serialize:
                    if field.rel is None:
                        if self.selected_fields is None or field.attname in self.selected_fields:
                            self.handle_field(obj, field)
                    else:
                        if self.selected_fields is None or field.attname[:-3] in self.selected_fields:
                            self.handle_fk_field(obj, field)
            for field in obj._meta.many_to_many:
                if field.serialize:
                    if self.selected_fields is None or field.attname in self.selected_fields:
                        self.handle_m2m_field(obj, field)
            self.end_object(obj)
        self.end_serialization()
        return self.getvalue()

    def handle_field(self, obj, field):
        # A nasty special case: base YAML doesn't support serialization of time
        # types (as opposed to dates or datetimes, which it does support). Since
        # we want to use the "safe" serializer for better interoperability, we
        # need to do something with those pesky times. Converting 'em to strings
        # isn't perfect, but it's better than a "!!python/time" type which would
        # halt deserialization under any other language.
        if isinstance(field, models.TimeField) and getattr(obj, field.name) is not None:
            self._current[field.name] = str(getattr(obj, field.name))
        elif isinstance(field, models.FileField) and getattr(obj, field.name) is not None:
            # Get a sha512 of the File
            f = getattr(obj, field.name).open()
            if not f:
                # TODO : Ugly no?
                f = open(getattr(obj, field.name).name, 'rb')
            f.seek(0)
            sha = sha512()
            data = f.read(512)
            while len(data):
                sha.update(data) 
                data = f.read(512)
            self._current[field.name] = str(sha.hexdigest())
        else:
            super(SMIMESerializer, self).handle_field(obj, field)

    def handle_fk_field(self, obj, field):
        related = getattr(obj, field.name)
        if related is not None:
            if self.use_natural_keys and hasattr(related, 'natural_key'):
                related = related.natural_key()
            else:
                if field.rel.field_name == related._meta.pk.name:
                    # Related to remote object via primary key
                    related = related._get_pk_val()
                else:
                    # Related to remote object via other field
                    related = smart_unicode(getattr(related, field.rel.field_name), strings_only=True)
        self._current[field.name] = related

    def end_serialization(self):
        self.options.pop('stream', None)
        self.options.pop('fields', None)
        self.options.pop('use_natural_keys', None)
        yaml.dump(self.objects, self.stream, Dumper=DjangoSafeDumper, **self.options)

def serialize(obj, use_natural_keys=False):
    """
    """
    data = [obj]
    serializer = SMIMESerializer()
    serialized = serializer.serialize(data, use_natural_keys=use_natural_keys)
    return serialized
