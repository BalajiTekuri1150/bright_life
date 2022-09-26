from django.contrib import admin

from .models import BankDetails,Country,CountryState,EnumGender,EnumApplicationStatus,EnumChildType, EnumUserRole, OtpMaster,User,Sponsor,Application,ApplicationDocument,EnumDocumentType,Sponsorship
# Register your models here.


admin.site.register(BankDetails)
admin.site.register(Country)
admin.site.register(CountryState)
admin.site.register(EnumGender)
admin.site.register(EnumApplicationStatus)
admin.site.register(EnumChildType)
admin.site.register(User)
admin.site.register(Sponsor)
admin.site.register(Application)
admin.site.register(ApplicationDocument)
admin.site.register(EnumDocumentType)
admin.site.register(Sponsorship)
admin.site.register(EnumUserRole)
admin.site.register(OtpMaster)
