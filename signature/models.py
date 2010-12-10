from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import smart_str, smart_unicode
from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509, SMIME
from M2Crypto.util import no_passphrase_callback
from signature import utils
from tempfile import NamedTemporaryFile, TemporaryFile
from signature.openssl import Openssl

from datetime import datetime

COUNTRY = (
    ('AD', 'AD'),('AE', 'AE'),('AF', 'AF'),('AG', 'AG'),('AI', 'AI'),('AL', 'AL'),('AM', 'AM'),
    ('AN', 'AN'),('AO', 'AO'),('AQ', 'AQ'),('AR', 'AR'),('AS', 'AS'),('AT', 'AT'),('AU', 'AU'),
    ('AW', 'AW'),('AZ', 'AZ'),('BA', 'BA'),('BB', 'BB'),('BD', 'BD'),('BE', 'BE'),('BF', 'BF'),
    ('BG', 'BG'),('BH', 'BH'),('BI', 'BI'),('BJ', 'BJ'),('BM', 'BM'),('BN', 'BN'),('BO', 'BO'),
    ('BR', 'BR'),('BS', 'BS'),('BT', 'BT'),('BU', 'BU'),('BV', 'BV'),('BW', 'BW'),('BY', 'BY'),
    ('BZ', 'BZ'),('CA', 'CA'),('CC', 'CC'),('CF', 'CF'),('CG', 'CG'),('CH', 'CH'),('CI', 'CI'),
    ('CK', 'CK'),('CL', 'CL'),('CM', 'CM'),('CN', 'CN'),('CO', 'CO'),('CR', 'CR'),('CS', 'CS'),
    ('CU', 'CU'),('CV', 'CV'),('CX', 'CX'),('CY', 'CY'),('CZ', 'CZ'),('DD', 'DD'),('DE', 'DE'),
    ('DJ', 'DJ'),('DK', 'DK'),('DM', 'DM'),('DO', 'DO'),('DZ', 'DZ'),('EC', 'EC'),('EE', 'EE'),
    ('EG', 'EG'),('EH', 'EH'),('ER', 'ER'),('ES', 'ES'),('ET', 'ET'),('FI', 'FI'),('FJ', 'FJ'),
    ('FK', 'FK'),('FM', 'FM'),('FO', 'FO'),('FR', 'FR'),('FX', 'FX'),('GA', 'GA'),('GB', 'GB'),
    ('GD', 'GD'),('GE', 'GE'),('GF', 'GF'),('GH', 'GH'),('GI', 'GI'),('GL', 'GL'),('GM', 'GM'),
    ('GN', 'GN'),('GP', 'GP'),('GQ', 'GQ'),('GR', 'GR'),('GS', 'GS'),('GT', 'GT'),('GU', 'GU'),
    ('GW', 'GW'),('GY', 'GY'),('HK', 'HK'),('HM', 'HM'),('HN', 'HN'),('HR', 'HR'),('HT', 'HT'),
    ('HU', 'HU'),('ID', 'ID'),('IE', 'IE'),('IL', 'IL'),('IN', 'IN'),('IO', 'IO'),('IQ', 'IQ'),
    ('IR', 'IR'),('IS', 'IS'),('IT', 'IT'),('JM', 'JM'),('JO', 'JO'),('JP', 'JP'),('KE', 'KE'),
    ('KG', 'KG'),('KH', 'KH'),('KI', 'KI'),('KM', 'KM'),('KN', 'KN'),('KP', 'KP'),('KR', 'KR'),
    ('KW', 'KW'),('KY', 'KY'),('KZ', 'KZ'),('LA', 'LA'),('LB', 'LB'),('LC', 'LC'),('LI', 'LI'),
    ('LK', 'LK'),('LR', 'LR'),('LS', 'LS'),('LT', 'LT'),('LU', 'LU'),('LV', 'LV'),('LY', 'LY'),
    ('MA', 'MA'),('MC', 'MC'),('MD', 'MD'),('MG', 'MG'),('MH', 'MH'),('ML', 'ML'),('MM', 'MM'),
    ('MN', 'MN'),('MO', 'MO'),('MP', 'MP'),('MQ', 'MQ'),('MR', 'MR'),('MS', 'MS'),('MT', 'MT'),
    ('MU', 'MU'),('MV', 'MV'),('MW', 'MW'),('MX', 'MX'),('MY', 'MY'),('MZ', 'MZ'),('NA', 'NA'),
    ('NC', 'NC'),('NE', 'NE'),('NF', 'NF'),('NG', 'NG'),('NI', 'NI'),('NL', 'NL'),('NO', 'NO'),
    ('NP', 'NP'),('NR', 'NR'),('NT', 'NT'),('NU', 'NU'),('NZ', 'NZ'),('OM', 'OM'),('PA', 'PA'),
    ('PE', 'PE'),('PF', 'PF'),('PG', 'PG'),('PH', 'PH'),('PK', 'PK'),('PL', 'PL'),('PM', 'PM'),
    ('PN', 'PN'),('PR', 'PR'),('PT', 'PT'),('PW', 'PW'),('PY', 'PY'),('QA', 'QA'),('RE', 'RE'),
    ('RO', 'RO'),('RU', 'RU'),('RW', 'RW'),('SA', 'SA'),('SB', 'SB'),('SC', 'SC'),('SD', 'SD'),
    ('SE', 'SE'),('SG', 'SG'),('SH', 'SH'),('SI', 'SI'),('SJ', 'SJ'),('SK', 'SK'),('SL', 'SL'),
    ('SM', 'SM'),('SN', 'SN'),('SO', 'SO'),('SR', 'SR'),('ST', 'ST'),('SU', 'SU'),('SV', 'SV'),
    ('SY', 'SY'),('SZ', 'SZ'),('TC', 'TC'),('TD', 'TD'),('TF', 'TF'),('TG', 'TG'),('TH', 'TH'),
    ('TJ', 'TJ'),('TK', 'TK'),('TM', 'TM'),('TN', 'TN'),('TO', 'TO'),('TP', 'TP'),('TR', 'TR'),
    ('TT', 'TT'),('TV', 'TV'),('TW', 'TW'),('TZ', 'TZ'),('UA', 'UA'),('UG', 'UG'),('UM', 'UM'),
    ('US', 'US'),('UY', 'UY'),('UZ', 'UZ'),('VA', 'VA'),('VC', 'VC'),('VE', 'VE'),('VG', 'VG'),
    ('VI', 'VI'),('VN', 'VN'),('VU', 'VU'),('WF', 'WF'),('WS', 'WS'),('YD', 'YD'),('YE', 'YE'),
    ('YT', 'YT'),('YU', 'YU'),('ZA', 'ZA'),('ZM', 'ZM'),('ZR', 'ZR'),('ZW', 'ZW'),('ZZ', 'ZZ'),
    ('ZZ', 'ZZ'),
    )

class BaseCert(models.Model):
    """Base Certificate for Models
    """
    key = models.ForeignKey('Key', null=True)
    pem = models.TextField(editable=False)
    country = models.CharField(max_length=2, choices=COUNTRY)
    state  = models.CharField(max_length=32, null=True)
    locality = models.CharField(max_length=32, null=True)
    organization = models.CharField(max_length=64, null=True)
    created = models.DateTimeField()
    CN = models.CharField(max_length=50)
    OU = models.CharField(max_length=50, null=True)
    email = models.EmailField(blank=True, null=True)
    user = models.ForeignKey(User, null=True)
    class Meta:
        abstract = True

    def get_subject(self):
        """Return subject string for CSR and self-signed certs
        """

        subj = '/CN=%s' % self.CN

        if self.country:
            subj += '/C=%s' % self.country
        if self.state:
            subj += '/ST=%s' % self.state
        if self.locality:
            subj += '/localityName=%s' % self.locality
        if self.organization:
            subj += '/O=%s' % self.organization
        if self.OU:
            subj += '/organizationalUnitName=%s' % self.OU
        if self.email:
            subj += '/emailAddress=%s' % self.email
        return subj

    def get_pubkey(self):
        """Retrieve pubkey of certificate
        """
        bio = BIO.MemoryBuffer()
        self.m2_x509().get_pubkey().get_rsa().save_pub_key_bio(bio)
        return bio.read()

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

    TODO : RSA/EVP ??
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
        rsakeyp = RSA.load_key_string(smart_str(self.private), cb)
        return rsakeyp

    def m2_pkey(self, passphrase=None):
        """Return M2Crypto EVP's instance of key
        """
        rsakeyp = self.m2_rsa(passphrase)
        ciph, cb = quiet_passphrase(passphrase)
        evp_pkey = EVP.PKey(md='sha1')
        evp_pkey.assign_rsa(rsakeyp)
        return evp_pkey

    @classmethod
    def new_from_pem(cls, pem, passphrase=None, user=None):
        """Create a Key Instance with an existing PEM
        """
        ciph, cb = quiet_passphrase(passphrase)
        key = cls(user=user)
        m2key = RSA.load_key_string(pem, cb)
        key.private = m2key.as_pem(ciph, cb)
        bio = BIO.MemoryBuffer()
        m2key.save_pub_key_bio(bio)
        key.public = bio.read()
        key.length = len(m2key)

        key.save()
        # Find Relations
        if user:
            for cert in Certificate.objects.filter(user=user, key__isnull=True):
                if cert.get_pubkey() == key.public:
                    cert.key = key
                    cert.save()
            for rqst in CertificateRequest.objects.filter(user=user, key__isnull=True):
                if rqst.get_pubkey() == key.public:
                    rqst.key = key
                    rqst.save()
        else:
            for cert in Certificate.objects.filter(user__isnull=True, key__isnull=True):
                if cert.get_pubkey() == key.public:
                    cert.key = key
                    cert.save()
            for rqst in CertificateRequest.objects.filter(user__isnull=True, key__isnull=True):
                if rqst.get_pubkey() == key.public:
                    rqst.key = key
                    rqst.save()
        return key

class CertificateRequest(BaseCert):
    """A CSR
    """

    def m2_request(self):
        """Return M2Crypto's Request instance
        """
        rqst = X509.load_request_string(self.pem, X509.FORMAT_PEM)
        return rqst

    def sign_request(self, passphrase=None):
        """Generate request with instance informations
        """
        # TODO : class for C / CN and all attributes
        # Generate CA Request
        rqst = X509.Request()
        issuer_name = rqst.get_subject()
        issuer_name.CN = self.CN
        if self.country:
            issuer_name.C = self.country
        if self.locality:
            issuer_name.L = self.locality
        if self.organization:
            issuer_name.O = self.organization
        if self.OU:
            issuer_name.OU = self.OU
        if self.state:
            issuer_name.SP = self.state
        if self.email:
            issuer_name.Email = self.email
        issuer_pkey = self.key.m2_pkey(passphrase)
        rqst.set_pubkey(issuer_pkey)
        rqst.sign(pkey=issuer_pkey, md='sha1')
        # Add date
        self.created = datetime.now()
        self.pem = rqst.as_pem()

    @classmethod
    def new_from_pem(cls, pem, user=None, key=None):
        """Create a Request Instance with an existing PEM
        """
        rqst = cls(user=user, key=key)
        m2rqst = X509.load_request_string(pem, X509.FORMAT_PEM)
        rqst.pem = m2rqst.as_pem()
        subject = m2rqst.get_subject()
        rqst.country = subject.C
        rqst.CN = subject.CN
        # Add date
        rqst.created = datetime.now()
        return rqst

    def __unicode__(self):
        return "CSR %s" % self.get_subject()

class Signature(models.Model):
    """A PKCS#7 signature for a model
    """
    certificate = models.ForeignKey('Certificate')
    object_id = models.PositiveIntegerField(null=True)
    content_type = models.ForeignKey(ContentType, null=True)
    content_object = generic.GenericForeignKey('content_type', 'object_id')
    pkcs7 = models.TextField()

    def check_pkcs7(self):
        """Check PKCS7 signature
        (don't compare with original model)
        """
        pkcs7 = smart_str(self.pkcs7)
        return self.certificate.verify_smime(pkcs7)

    def check(self):
        """Check Signature
        """
        pkcs7_data = self.check_pkcs7()
        if not pkcs7_data:
            return False
        # TODO : That is ugly !
        pkcs7_data = pkcs7_data.replace("\r\n", "\n")
        serialized = utils.serialize(self.content_object)
        return serialized == pkcs7_data

class Certificate(BaseCert):
    """An x509 certificate
    """
    begin = models.DateTimeField(editable=False)
    end = models.DateTimeField(editable=False)
    days = models.IntegerField(null=True)
    serial = models.CharField(max_length=21, editable=False)
    issuer = models.ForeignKey('self', related_name='issuer_set', null=True)
    is_ca = models.BooleanField(default=False)
    ca_serial = models.PositiveIntegerField(null=True, editable=False)
    subject_kid = models.CharField(max_length=60, editable=False)
    auth_kid = models.CharField(max_length=60, editable=False)
    crl = models.TextField(editable=False, null=True, blank=True)
    crlnumber = models.PositiveIntegerField(editable=False, null=True, blank=True)
    revoked = models.BooleanField(editable=False, default=False)
    trust = models.NullBooleanField(editable=False, null=True)
    certhash = models.CharField(editable=False, max_length=9)
    index = models.TextField(editable=False, default="") # temporary

    def __unicode__(self):
        if self.is_ca:
            return "x509 CA %s" % self.get_subject()
        else:
            return "x509 %s" % self.get_subject()

    class Meta:
        unique_together = (("subject_kid", "serial"))

    def m2_x509(self):
        """Return M2Crypto's x509 instance of certificate
        """
        pem = smart_str(self.pem)
        cert = X509.load_cert_string(pem, X509.FORMAT_PEM)
        return cert

    def generate_x509_root(self, passphrase=None):
        """Generate x509 certificate with instance informations
        """
        # Generate CA Request
        ca_pkey = self.key.private

        subject = self.get_subject()

        ossl = Openssl()
        pem = ossl.generate_self_signed_cert(self.days, subject, ca_pkey, passphrase)
        self.pem = pem
        self.certhash = ossl.get_hash_from_cert(pem)
        x509 = X509.load_cert_string(pem, X509.FORMAT_PEM)
        self.serial = str(x509.get_serial_number())
        self.begin = x509.get_not_before().get_datetime()
        self.end = x509.get_not_after().get_datetime()
        # v3 extensions
        self.subject_kid = x509.get_ext("subjectKeyIdentifier").get_value().strip()
        auth_kid = x509.get_ext("authorityKeyIdentifier").get_value().split("\n")
        self.auth_kid = [keyid.lstrip('keyid:') for keyid in auth_kid if keyid.startswith("keyid:")][0].strip()
        self.ca_serial = 1
        self.is_ca = True
        self.trust = True
        # Add date
        self.created = datetime.now()

    def sign_request(self, rqst, days, passphrase=None, ca=False):
        """Sign a Request and return a Certificate instance
        """
        ossl = Openssl()

        pem = ossl.sign_csr(rqst.pem, self.key.private, self.pem, self.ca_serial, days, passphrase, ca)
        self.ca_serial += 1
        self.save()

        c_cert = Certificate()
        c_cert.pem = pem
        c_cert.certhash = ossl.get_hash_from_cert(pem)
        c_cert.user = rqst.user
        c_cert.issuer = self
        c_cert.key = rqst.key
        c_cert.country = rqst.country
        c_cert.CN = rqst.CN
        c_cert.locality = rqst.locality
        c_cert.email = rqst.email
        c_cert.organization = rqst.organization
        c_cert.OU = rqst.OU
        c_cert.state = rqst.state

        x509 = X509.load_cert_string(pem, X509.FORMAT_PEM)
        c_cert.serial = str(x509.get_serial_number())
        c_cert.begin = x509.get_not_before().get_datetime()
        c_cert.end = x509.get_not_after().get_datetime()
        # v3 extensions
        c_cert.subject_kid = x509.get_ext("subjectKeyIdentifier").get_value().strip()
        auth_kid = x509.get_ext("authorityKeyIdentifier").get_value().split("\n")
        c_cert.auth_kid = [keyid.lstrip('keyid:') for keyid in auth_kid if keyid.startswith("keyid:")][0].strip()
        if ca:
            c_cert.ca_serial = 1
            c_cert.is_ca = True
        # Add date
        c_cert.created = datetime.now()

        # And return new instance
        return c_cert

    @classmethod
    def new_from_pem(cls, pem, user=None, key=None):
        """Create a Certificate Instance with an existing PEM
        """
        ossl = Openssl()
        cert = cls(user=user, key=key)
        x509 = X509.load_cert_string(pem, X509.FORMAT_PEM)
        cert.pem = x509.as_pem()
        cert.certhash = ossl.get_hash_from_cert(pem)
        issuer = x509.get_issuer()
        if issuer.C:
            cert.country = smart_unicode(issuer.C)
        cert.CN = smart_unicode(issuer.CN)
        if issuer.L:
            cert.locality = smart_unicode(issuer.L)
        if issuer.Email:
            cert.email = smart_unicode(issuer.Email)
        if issuer.O:
            cert.organization = smart_unicode(issuer.O)
        if issuer.OU:
            cert.OU = smart_unicode(issuer.OU)
        if issuer.SP:
            cert.state = smart_unicode(issuer.SP)
        cert.serial = str(x509.get_serial_number())
        cert.begin = x509.get_not_before().get_datetime()
        cert.end = x509.get_not_after().get_datetime()
        # v3 extensions
        cert.subject_kid = x509.get_ext("subjectKeyIdentifier").get_value().strip()
        auth_kid = x509.get_ext("authorityKeyIdentifier").get_value().split("\n")
        cert.auth_kid = [keyid.lstrip('keyid:') for keyid in auth_kid if keyid.startswith("keyid:")][0].strip()

        # Search issuer
        try:
            ca_cert = Certificate.objects.get(subject_kid=cert.auth_kid)
        except Certificate.DoesNotExist:
            pass
        else:
            cert.issuer = ca_cert

        # Find Relations
        cert_pubkey = cert.get_pubkey()
        if key:
            cert.key = key
        else:
            if user:
                try:
                    key = Key.objects.get(user=user, public=cert_pubkey)
                except Key.DoesNotExist:
                    pass
                else:
                    cert.key = key
            else:
                try:
                    key = Key.objects.get(public=cert_pubkey)
                except Key.DoesNotExist:
                    pass
                else:
                    cert.key = key
                    cert.user = key.user
        # Add date
        cert.created = datetime.now()
        if x509.check_ca():
            cert.is_ca = True
        cert.save()

        # Search issued # XXX
        for c_cert in Certificate.objects.filter(auth_kid=cert.subject_kid, issuer__isnull=True):
            c_cert.issuer = cert
            c_cert.save()

        return cert

    def sign_text(self, text, passphrase):
        """Sign a text with cert's key and passphrase
        """
        if not self.key:
            raise Exception("No key for this certificate")

        ossl = Openssl()
        data_signed = ossl.sign_pkcs7(self.pem, text, self.key.private, passphrase)
        return data_signed

    def get_issued(self):
        """Retrieve all certificates issued by the certificate
        """
        chain = Certificate.objects.filter(issuer=self)
        return chain

    def get_cert_chain(self):
        """Retrieve all certificates of the certificate chain
        """
        chain = []
        current_cert = self
        while current_cert:
            chain.append(current_cert)
            current_cert = current_cert.issuer
        chain.reverse()
        return chain

    def get_cert_chain_aspem(self):
        """Retrieve all certificates of the certificate chain
        as pem
        """
        pemchain = []
        chain = self.get_cert_chain()
        for cert in chain:
            crlchain.append(cert.pem)
        return crlchain

    def get_crl_chain_aspem(self):
        """Retrieve all crls of the certificate chain
        """
        crlchain = []
        chain = self.get_cert_chain()
        for cert in chain:
            if cert.crl:
                crlchain.append(cert.crl)
        return crlchain

    def check_chain(self, chain=None, silent=False):
        """Check certificate chain
        """
        if not chain:
            chain = self.get_cert_chain()
        ossl = Openssl()
        result = False
        if silent:
            try:
                result = ossl.verify_ca_chain(chain)
            except ossl.VerifyError:
                return False
        else:
            result = ossl.verify_ca_chain(chain)
        return result

    def check_crl(self, silent=False, quick=False):
        """Check CRL for this certificate

        Quick only use database cache
        """
        if self.revoked:
            return False
        elif quick:
            return True
        if self.issuer:
            if self.issuer.crl:
                ossl = Openssl()
                return not ossl.get_revoke_status_from_cert(self, self.issuer.crl)
        elif self.subject_kid != self.auth_kid:
            return False
        return True

    def check_crl_chain(self, chain=None, silent=False, quick=False):
        """Check CRL chain

        Quick only use database cache
        """
        for cert in chain:
            if not cert.check_crl(silent, quick):
                return False
        return True

    def check(self, silent=False, quick=False, crlcheck=True):
        """Check certificate
        """
        chain = self.get_cert_chain()
        chain_valid = self.check_chain(chain, silent)
        crl_valid = False
        if crlcheck:
            crl_valid = self.check_crl_chain(chain, silent, quick)
        return chain_valid and (crl_valid or not crlcheck)

    def gen_crl(self, passphrase=""):
        """Generate CRL for this certificate
        """
        cakey = self.key.private
        issued = self.get_issued()
        crlnumber = self.crlnumber or 1
        ossl = Openssl()
        self.crl = ossl.generate_crl(self, cakey, crlnumber, self.crl, issued, passphrase=passphrase)
        self.crlnumber = crlnumber + 1
        self.save()
        return self.crl

    def revoke(self, cert, passphrase=""):
        """Generate CRL for this certificate
        """
        if cert.issuer != self:
            raise Exception("I'm not the issuer.")

        cakey = self.key.private
        issued = self.get_issued()
        crlnumber = self.crlnumber or 1
        ossl = Openssl()
        self.crl, self.index = ossl.revoke_cert(self, cakey, crlnumber, self.crl, cert, issued, passphrase=passphrase)
        self.crlnumber = crlnumber + 1
        self.save()
        cert.revoked = True
        cert.save()
        return self.crl

    def sign_model(self, obj, passphrase, use_natural_keys=False, *args, **kwargs):
        """Sign a model instance or a queryset
        """
        serialized = utils.serialize(obj, use_natural_keys=use_natural_keys, *args, **kwargs)
        signed = self.sign_text(serialized, passphrase)
        return signed

    def verify_smime(self, smime, silent=False):
        """Verify an smime signed message
        """
        if not self.key:
            raise Exception("No key for this certificate")

        ossl = Openssl()
        if silent:
            try:
                data_signed = ossl.verify_pkcs7(self.pem, smime)
            except ossl.VerifyError:
                return False
        else:
            data_signed = ossl.verify_pkcs7(self.pem, smime)
        return data_signed

    def make_signature(self, instance, passphrase, fields=[], exclude=[]):
        """Sign a Model instance with passphrase
        """
        if not self.key:
            raise Exception("No key for this certificate")

        signature = Signature()

        signature.pkcs7 = self.sign_model(instance, passphrase)
        signature.certificate = self
        signature.content_type = ContentType.objects.get_for_model(instance)
        signature.object_id = instance.id
        return signature
