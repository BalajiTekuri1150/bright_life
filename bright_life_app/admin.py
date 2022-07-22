from django.contrib import admin

from .models import KidDetails,Child,GuardianDetails,BankAccount,Country,CountryState,EnumGender,EnumChildStatus,EnumChildType,EnumDocumentType
# Register your models here.

admin.site.register(KidDetails)
admin.site.register(Child)
admin.site.register(GuardianDetails)
admin.site.register(BankAccount)
admin.site.register(Country)
admin.site.register(CountryState)
admin.site.register(EnumGender)
admin.site.register(EnumChildStatus)
admin.site.register(EnumChildType)
admin.site.register(EnumDocumentType)