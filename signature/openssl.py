"""
From django-pki - Copyright (C) 2010 Daniel Kerwin <django-pki@linuxaddicted.de>
    http://github.com/dkerwin/django-pki

                - Copyright (C) 2010 Johan Charpentier <jcharpentier@bearstech.com>


This program and entire repository is free software; you can
redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software
Foundation; either version 2 of the License, or any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; If not, see <http://www.gnu.org/licenses/>.
"""
import os, re, sys
import datetime
import string, random

from signature.settings import PKI_OPENSSL_BIN, PKI_OPENSSL_CONF, PKI_DIR, PKI_OPENSSL_TEMPLATE, PKI_SELF_SIGNED_SERIAL

from subprocess import Popen, PIPE, STDOUT
from shutil import rmtree
from logging import getLogger
from tempfile import NamedTemporaryFile, TemporaryFile

try:
    # available in python-2.5 and greater
    from hashlib import md5 as md5_constructor
except ImportError:
    # compatibility fallback
    from md5 import new as md5_constructor

from django.template.loader import render_to_string

logger = getLogger("pki")

##------------------------------------------------------------------##
## OpenSSLConfig: Config related stuff
##------------------------------------------------------------------##

def refresh_pki_metadata(ca_list):
    """Refresh pki metadata (PKI storage directories and openssl configuration files)

    Each ca_list element is a dictionary:
    'name': CA name
    'subcas_allowed': sub CAs allowed (boolean)
    """

    status = True

    # refresh directory structure
    dirs = { 'certs'  : 0755,
             'private': 0700,
             'crl'    : 0755,
           }

    try:
        # create base PKI directory if necessary
        if not os.path.exists(PKI_DIR):
            logger.info('Creating base PKI directory')
            os.mkdir(PKI_DIR, 0700)

        # list of old CA directories for possible purging
        purge_dirs = set([os.path.join(PKI_DIR, d) for d in os.listdir(PKI_DIR)
                          if os.path.isdir(os.path.join(PKI_DIR, d))])

        # loop over CAs and create necessary filesystem objects
        for ca in ca_list:
            ca_dir = os.path.join(PKI_DIR, ca.name)

            # create CA directory if necessary
            if not ca_dir in purge_dirs:
                logger.info('Creating base directory for CA %s' % ca.name)
                os.mkdir(ca_dir)

                # create nested directories for key storage with proper permissions
                for d, m in dirs.items():
                    os.mkdir(os.path.join(ca_dir, d), m)

                initial_serial = 0x01

                try:
                    if not ca.parent and int(PKI_SELF_SIGNED_SERIAL) > 0:
                        initial_serial = PKI_SELF_SIGNED_SERIAL+1
                except ValueError:
                    logger.error( "PKI_SELF_SIGNED_SERIAL failed conversion to int!" )

                h2s = '%X' % initial_serial

                if len(h2s) % 2 == 1:
                    h2s = '0' + h2s

                # initialize certificate serial number
                s = open(os.path.join(ca_dir, 'serial'), 'wb')
                s.write(h2s)
                s.close()

                # initialize CRL serial number
                s = open(os.path.join(ca_dir, 'crlnumber'), 'wb')
                s.write('01')
                s.close()

                # touch certificate index file
                open(os.path.join(ca_dir, 'index.txt'), 'wb').close()

            # do not delete existing CA dir
            purge_dirs.discard(ca_dir)

        # purge unused CA directories
        for d in purge_dirs:
            if os.path.isdir(d):
                # extra check in order to keep unrelated directory from recursive removal...
                # (in case if something wrong with paths)
                # probably can be removed when debugging will be finished
                if os.path.isfile(os.path.join(d, 'crlnumber')):
                    logger.debug("Purging CA directory tree %s" % d)
                    rmtree(d) # FIXME: commented for debugging purposes
                else:
                    logger.warning('Directory %s does not contain any metadata, preserving it' % d)

    except OSError, e: # FIXME: probably catch any exception here, not just OS
        status = False
        logger.error("Refreshing directory structure failed: %s" % e)

    # prepare context for template rendering
    ctx = {'ca_list': ca_list}

    # render template and save result to openssl.conf
    try:
        conf = render_to_string(PKI_OPENSSL_TEMPLATE, ctx)

        f = open(PKI_OPENSSL_CONF, 'wb')
        f.write(conf)
        f.close()

    except:
        raise Exception( 'Failed to render OpenSSL template' )
        status = False

    return status # is it used somewhere?

##------------------------------------------------------------------##
## OpenSSLActions: All non config related actions
##------------------------------------------------------------------##

class Openssl():
    '''Do the real openssl work - Generate keys, csr, sign'''

    def __init__(self):
        '''Class constructor'''

        ## Generate a random string as ENV variable name
        self.env_pw = "".join(random.sample(string.letters+string.digits, 10))

        self.conf = NamedTemporaryFile()
        self.conf.write(PKI_OPENSSL_CONF)
        self.conf.seek(0)
        self.confname = self.conf.name

    def exec_openssl(self, command, stdin ,env_vars=None):
        '''Run openssl command. PKI_OPENSSL_BIN doesn't need to be specified'''

        c = [PKI_OPENSSL_BIN]
        c.extend(command)

        # add PKI_DIR environment variable if caller did not set it
        if env_vars:
            env_vars.setdefault('PKI_DIR', PKI_DIR)
        else:
            env_vars = {'PKI_DIR': PKI_DIR}

        proc = Popen(c, shell=False, env=env_vars, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        stdout_value, stderr_value = proc.communicate(stdin)

        if proc.returncode != 0:
            logger.error('openssl command "%s" failed with returncode %d' % (c[1], proc.returncode))
            logger.error(stdout_value)

            raise Exception(stdout_value)
        else:
            return stdout_value

    def generate_key(self):
        '''Generate the secret key'''

        logger.info( 'Generating private key' )

        key_type = po = pf = ''

        if self.i.passphrase:
            key_type = '-des3'
            po = '-passout'
            pf = 'env:%s' % self.env_pw

        command = 'genrsa %s -out %s %s %s %s' % (key_type, self.key, po, pf, self.i.key_length)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(self.i.passphrase) } )

    def generate_self_signed_cert(self, days, subj, key, passphrase=None):
        """Generate a self signed root certificate
        """
        key_f = NamedTemporaryFile()
        key_f.write(key)
        key_f.seek(0)

        logger.info( 'Generating self-signed root certificate' )

        #command = ['req', '-config', self.confname, '-batch', '-sha1', '-new', '-x509', '-subj', subj, '-days', str(days), \
        command = ['req', '-batch', '-sha1', '-new', '-x509', '-subj', subj, '-days', str(days), \
                   '-extensions', 'v3_ca', '-key', key_f.name, '-passin', 'stdin']

        pem = self.exec_openssl(command, stdin=passphrase)
        return pem

    def generate_csr(self):
        '''Generate the CSR'''

        logger.info( 'Generating the CSR for %s' % self.i.name )

        command = ['req', '-config', PKI_OPENSSL_CONF, '-new', '-batch', '-subj', self.subj, '-key', self.key, '-out', self.csr, \
                   '-days', str(self.i.valid_days), '-passin', 'env:%s' % self.env_pw]
        self.exec_openssl(command, env_vars={ self.env_pw: str(self.i.passphrase) })

    def generate_der_encoded(self):
        '''Generate a DER encoded version of a given certificate'''

        logger.info( 'Generating DER encoded certificate for %s' % self.i.name )

        command = 'x509 -in %s -out %s -outform DER' % (self.crt, self.der)
        self.exec_openssl(command.split())

        return True

    def sign_csr(self, csr, cakey, cacrt, serial, days, passphrase=None, ca_capable=False):
        '''Sign the CSR with given CA'''

        logger.info( 'Signing CSR' )

        if ca_capable:
            extension = "v3_ca"
        else:
            extension = "usr_cert"
        csrfile = NamedTemporaryFile()
        csrfile.write(csr)
        csrfile.seek(0)
        cafile = NamedTemporaryFile()
        cafile.write(cacrt)
        cafile.seek(0)
        cakeyfile = NamedTemporaryFile()
        cakeyfile.write(cakey)
        cakeyfile.seek(0)
        serialfile = NamedTemporaryFile()
        serialfile.write(str(serial).rjust(2,"0"))
        serialfile.seek(0)

        command = ['x509', '-req', '-CAserial', serialfile.name,'-extfile', self.confname , '-sha1', '-days', str(days), '-in', csrfile.name, '-CA', cafile.name, '-CAkey', cakeyfile.name, '-passin', 'stdin', '-extensions', extension]
        pem = self.exec_openssl(command, stdin=passphrase)
        return pem

    def revoke_certificate(self, ppf):
        '''Revoke a given certificate'''

        ## Check if certificate is already revoked. May have happened during a incomplete transaction
        if self.get_revoke_status_from_cert():
            logger.info( "Skipping revoke as it already happened" )
            return True

        logger.info( 'Revoking certificate %s' % self.i.name )

        command = 'ca -config %s -name %s -batch -revoke %s -passin env:%s' % (PKI_OPENSSL_CONF, self.i.parent, self.crt, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(ppf) })

    def renew_certificate(self):
        '''Renew/Reissue a given certificate'''

        logger.info( 'Renewing certificate %s' % self.i.name )

        if os.path.exists(self.csr):
            self.sign_csr()
        else:
            raise Exception( "Failed to renew certificate %s! CSR is missing!" % self.i.name )

    def generate_crl(self, ca=None, pf=None):
        '''Generate CRL: When a CA is modified'''

        logger.info( 'CRL generation for CA %s' % ca )

        crl = os.path.join(PKI_DIR, ca, 'crl', '%s.crl.pem' % ca)

        command = 'ca -config %s -name %s -gencrl -out %s -crldays 1 -passin env:%s' % (PKI_OPENSSL_CONF, ca, crl, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(pf) })

    def update_ca_chain_file(self):
        '''Build/update the CA chain'''

        ## Build list of parents
        chain = []
        chain_str = ''

        p = self.i.parent

        if self.i.parent == None:
            chain.append( self.i.name )
        else:
            chain.append( self.i.name )
            while p != None:
                chain.append(p.name)
                p = p.parent

        chain.reverse()

        chain_file = os.path.join( PKI_DIR, self.i.name, '%s-chain.cert.pem' % self.i.name )

        try:
            w = open(chain_file, 'w')

            for c in chain:
                cert_file = os.path.join( PKI_DIR, c, 'certs', '%s.cert.pem' % c )
                command = 'x509 -in %s' % cert_file
                output  = self.exec_openssl(command.split())

                ## Get the subject to print it first in the chain file
                subj = self.get_subject_from_cert(cert_file)

                w.write( '%s\n' % subj )
                w.write(output)

            w.close()
        except:
            raise Exception( 'Failed to write chain file!' )


    def get_hash_from_cert(self):
        '''Use openssl to get the hash value of a given certificate'''

        command = 'x509 -hash -noout -in %s' % self.crt
        output  = self.exec_openssl(command.split())

        return output.rstrip("\n")

    def get_subject_from_cert(self, cert):
        '''Get the subject form a given CA certificate'''

        command = 'x509 -noout -subject -in %s' % cert
        output  = self.exec_openssl(command.split())
        return output.rstrip("\n")

    def get_revoke_status_from_cert(self):
        '''Is the given certificate already revoked? True=yes, False=no'''

        command = 'crl -text -noout -in %s' % self.crl
        output  = self.exec_openssl(command.split())

        serial_re = re.compile('^\s+Serial\sNumber\:\s+(\w+)')
        lines = output.split('\n')

        for l in lines:
            if serial_re.match(l):
                if serial_re.match(l).group(1) == self.i.serial:
                    logger.info( "The certificate is revoked" )
                    return True

        return False
