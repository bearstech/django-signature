import os
from setuptools import setup, find_packages



readme = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

setup(
        name     = 'django-signature',
        version  = '0.3.1',
        packages = find_packages(exclude=['ez_setup', 'examples', 'test_project']),
        package_data = {'signature': ["openssl.cnf"]},
        include_package_data = True,

        requires = ['python (>= 2.4)', 'django (>= 1.1)', "M2Crypto (>= 0.18)"],

        description  = 'Django application to generate and sign Models.',
        long_description = readme,
        author       = 'Johan Charpentier',
        author_email = 'jcharpentier@bearstech.com',
        url          = 'http://github.com/bearstech/django-signature',
        download_url = 'http://bitbucket.org/bearstech/django-signature/downloads',
        license      = 'GPL v3',
        keywords     = 'django models crypto openssl pki',
        classifiers  = [
                    'Development Status :: 4 - Beta',
                    'Environment :: Web Environment',
                    'Framework :: Django',
                    'Intended Audience :: Developers',
                    'Programming Language :: Python',
                    'Topic :: Software Development :: Libraries :: Python Modules',
                ],
)

