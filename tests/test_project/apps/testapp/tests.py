from django.test import TestCase
from django.contrib.auth.models import User
from django.conf import settings
from django.http import HttpRequest, QueryDict
from datetime import date


class ATestCase(TestCase):
    def testBasic(self):
        """Test template
        """
        self.assertTrue()


