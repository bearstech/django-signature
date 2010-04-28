import os
DEBUG = True
DATABASE_ENGINE = 'sqlite3'
DATABASE_NAME = '/tmp/extjs.db'
INSTALLED_APPS = (
    'django.contrib.auth', 
    'django.contrib.contenttypes', 
    'django.contrib.sessions', 
    'django.contrib.sites',
    'signature',
    'test_project.apps.testapp',
)
TEMPLATE_DIRS = (
    os.path.join(os.path.dirname(__file__), 'templates'),
)

SITE_ID = 1
ROOT_URLCONF = 'test_project.urls'

