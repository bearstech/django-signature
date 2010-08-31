from django.contrib import admin
from models import Key, CertificateRequest, Signature, Certificate

class KeyAdmin(admin.ModelAdmin):
    pass
admin.site.register(Key, KeyAdmin)

class CertificateRequestAdmin(admin.ModelAdmin):
    pass
admin.site.register(CertificateRequest, CertificateRequestAdmin)

class SignatureAdmin(admin.ModelAdmin):
    pass
admin.site.register(Signature, SignatureAdmin)

class CertificateAdmin(admin.ModelAdmin):
    pass
admin.site.register(Certificate, CertificateAdmin)
