from django.contrib import admin
from models import Key, Request, Signature, Certificate

class KeyAdmin(admin.ModelAdmin):
    pass
admin.site.register(Key, KeyAdmin)

class RequestAdmin(admin.ModelAdmin):
    pass
admin.site.register(Request, RequestAdmin)

class SignatureAdmin(admin.ModelAdmin):
    pass
admin.site.register(Signature, SignatureAdmin)

class CertificateAdmin(admin.ModelAdmin):
    pass
admin.site.register(Certificate, CertificateAdmin)
