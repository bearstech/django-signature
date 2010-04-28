import os
from setuptools import setup



readme = open(os.path.join(os.path.dirname(__file__), 'README')).read()

setup(
        name     = 'django-signature',
        version  = '0.1',
        packages = ['signature'],

        requires = ['python (>= 2.4)', 'django (>= 1.0)'],

        description  = 'Django application to generate and sign Models.',
        long_description = readme,
        author       = 'Johan Charpentier',
        author_email = 'jcharpentier@bearstech.com',
        url          = 'http://github.com/bearstech/django-signature',
        download_url = '',
        license      = 'GPL v3',
        keywords     = 'django models crypto openssl',
        classifiers  = [
                    'Development Status :: 2 - Pre-Alpha',
                    'Environment :: Web Environment',
                    'Framework :: Django',
                    'Intended Audience :: Developers',
                    'Programming Language :: Python',
                    'Topic :: Software Development :: Libraries :: Python  Modules',
                ],
)

