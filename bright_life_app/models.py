from ast import Try
from datetime import datetime
from distutils.command.upload import upload
from email.policy import default
from locale import currency
from pickle import TRUE
from pyexpat import model
from re import M
from tkinter import CASCADE, Y
from unittest.util import _MAX_LENGTH
from django.db import models
from django.contrib.postgres.fields import JSONField
from django.core.validators import MinLengthValidator,MaxLengthValidator
from django.utils.timezone import now
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import FileExtensionValidator
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token 



# Create your models here.


class MyUserManager(BaseUserManager):
    def create_user(self,name,email,role,password=None,**kwargs):
        if not name:
            raise ValueError("Name is required")
        if not email:
            raise ValueError("Email is required")
        if not role:
            raise ValueError("Role is required")
        
        user = self.model(
            name = name,
            email = self.normalize_email(email),
            role = role
        )
        user.set_password(password)
        user.save(using = self._db)
        return user

    def create_superuser(self,name,email,role,password=None,**kwargs):
        user = self.create_user(
            email = self.normalize_email(email),
            name = name,
            role = role,
            password = password
        )
        user.is_admin = True
        user.is_superuser = True
        user.is_staff = True
        user.save(using = self._db)
        return user

class User(AbstractBaseUser):
    name = models.CharField(max_length=256,verbose_name="Name")
    email = models.EmailField(verbose_name="Email",max_length=60,unique=True)
    role = models.CharField(max_length=256,verbose_name="Role")
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="user")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="user")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['name','role']
    
    objects = MyUserManager()

    def __str__(self):
        return self.name

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self,app_label):
        return True


@receiver(post_save,sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender,instance=None,created=False,**kwargs):
    if created:
        Token.objects.create(user=instance)



class Country(models.Model):
    name = models.CharField(max_length=256)
    code = models.CharField(max_length=256,unique=True)
    isd_code = models.PositiveIntegerField()
    icon_url = models.CharField(max_length=256,blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.name



class CountryState(models.Model):
    name = models.CharField(max_length=256)
    code = models.CharField(max_length=256,unique=True)
    country = models.ForeignKey(Country,on_delete=models.CASCADE, verbose_name ="country_id")
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.name



class EnumGender(models.Model):
    name =models.CharField(max_length=256)
    gender = models.CharField(max_length=1)
    description = models.CharField(max_length=256,null=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.name
    

class EnumUserRole(models.Model):
    role = models.CharField(max_length=256)
    name =models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.role




class EnumApplicationStatus(models.Model):
    name = models.CharField(max_length=256)
    status = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.status



class EnumChildType(models.Model):
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.type

class EnumDocumentType(models.Model):
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=256)
    description = models.CharField(max_length=256,null=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return self.name


def get_profile_path(instance, filename):
    return 'profile/user_{0}/{1}'.format(instance.user.id, filename)


class Sponsor(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name="sponsor_user")
    mobile = PhoneNumberField(unique = True,null = True)
    organization = models.CharField(max_length=256,null=True)
    profile = models.ImageField(upload_to=get_profile_path,null = True)
    source = models.CharField(max_length=256,null=True)
    address = models.CharField(max_length=256,null=True)
    city = models.CharField(max_length=256,null=True)
    state = models.CharField(max_length=256,null=True)
    country = models.CharField(max_length=256,null=True)
    postal_code = models.CharField(max_length=256,null=True)
    zoho_id = models.CharField(max_length=25, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return str(self.id)


class Guardian(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name="guardian_user")
    mobile = PhoneNumberField(unique = True,null = True)
    organization = models.CharField(max_length=256,null=True)
    profile = models.ImageField(upload_to=get_profile_path,null = True)
    source = models.CharField(max_length=256,null=True)
    address = models.CharField(max_length=256,null=True)
    city = models.CharField(max_length=256,null=True)
    state = models.CharField(max_length=256,null=True)
    country = models.CharField(max_length=256,null=True)
    postal_code = models.CharField(max_length=256,null=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return str(self.id)



def get_application_profile_path(instance, filename):
    return 'profile/application_{0}/{1}'.format(instance.id, filename)

class Application(models.Model):
    name = models.CharField(max_length=100)
    birthday = models.DateField(null=True,blank=True)
    age = models.PositiveIntegerField(null=True,blank=True)
    gender = models.ForeignKey(EnumGender,on_delete=models.CASCADE)
    email = models.EmailField(max_length=250,null=True,blank=True,unique=False)
    mobile  = PhoneNumberField(unique = False,null = True,blank=True)
    profile = models.ImageField(upload_to=get_application_profile_path,null=True)
    child_type =  models.ForeignKey(EnumChildType,on_delete=models.CASCADE)
    country = models.ForeignKey(Country,on_delete=models.CASCADE,null=True)
    state = models.ForeignKey(CountryState,on_delete=models.CASCADE,null=True)
    region = models.CharField(max_length=256,null=True)
    grade = models.CharField(max_length = 20,null = True,blank = True)
    school = models.CharField(max_length = 250, null = True,blank=True)
    school_address = models.CharField(max_length = 256, null = True,blank=True)
    hobbies = models.TextField(max_length = 20,null = True,blank=True,default='')
    aspirations = models.TextField(null = True,blank=True,default='')
    status = models.ForeignKey(EnumApplicationStatus,on_delete=models.CASCADE,null=True,default=2,related_name="application_status")
    achievements = models.TextField(null=True,blank=True,default='')
    about = models.TextField(null=True,blank=True)
    profession = models.CharField(max_length=256,null=True,blank=True)
    annual_income = models.FloatField(null=True,blank=True)
    family_members = models.PositiveIntegerField(blank=True,null=True)
    extra_allowance = models.FloatField(null=True,blank=True)
    guardian = models.ForeignKey(Guardian,on_delete=models.CASCADE,null=True,related_name="guardian_id")
    zoho_id = models.CharField(max_length=25, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="user")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="user")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        ordering=('-id',)

def get_document_upload_path(instance, filename):
    return 'doc/application_{0}/{1}'.format(instance.application_id, filename)


class ApplicationDocument(models.Model):
    application = models.ForeignKey(Application,on_delete=models.CASCADE,null=True,related_name="applications")
    document_type = models.ForeignKey(EnumDocumentType,on_delete=models.CASCADE,null=True,blank=True)
    file_type = models.CharField(max_length=256,null=True,blank=True)
    url = models.FileField(upload_to=get_document_upload_path ,validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'img','png','jpg','jpeg'])],null=True,blank = True)
    seq_no = models.PositiveIntegerField(auto_created=True,default=1000)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default='system')
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default='system')
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return str(self.id)

    def delete(self,*args,**kwargs):
        self.url.delete()
        super().delete(*args,**kwargs)




class BankDetails(models.Model):
    application = models.OneToOneField(Application,on_delete=models.CASCADE,unique=True)
    bank_name = models.CharField(max_length = 256,null = True,blank=True)
    state = models.CharField(max_length=256,null=True,blank=True)
    postal_code = models.TextField(validators = [MinLengthValidator(6),MaxLengthValidator(6)],null=True,blank=True)
    account_holder = models.CharField(max_length = 20, unique = False,null = True,blank=True)
    account_number = models.TextField(validators = [MinLengthValidator(9),MaxLengthValidator(18)],null=True,blank=True)
    branch = models.CharField(max_length = 256,null = True)
    ifsc = models.CharField(max_length = 11,null = True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return f"{self.id} - {self.bank_name}"



class Sponsorship(models.Model):
    sponsor = models.ForeignKey(Sponsor,on_delete = models.CASCADE)
    pledge_date = models.DateField(auto_now_add=True)
    amount = models.FloatField(null=True,blank=True)
    currency_code = models.CharField(max_length=256, null=True,blank=True)
    billing_period = models.CharField(max_length=256,null=True,blank=True)
    type = models.CharField(max_length=256,null=True,blank=True)
    application = models.ForeignKey(Application,on_delete=models.SET_NULL, null=True, blank=True)
    start_date = models.DateField(null=True,blank=True)
    status = models.CharField(max_length=256,null=True)
    reference_id = models.CharField(max_length=256, null=True,blank=True)
    next_billing_at = models.DateTimeField(null=True,blank=True)
    subscription_data = models.JSONField(blank = True,null=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)


    def __str__(self):
        return f"{self.sponsor} - {self.application}"



class SponsorshipPayment(models.Model):
    sponsorship = models.ForeignKey(Sponsorship,on_delete=models.CASCADE)
    reference_id = models.CharField(max_length=256, null=True,blank=True)
    payment_date = models.DateField(null=True,blank=True)
    currency = models.CharField(max_length=256)
    amount = models.FloatField(null=True,blank=True)
    next_billing_at = models.DateTimeField(null=True,blank=True)
    billing_period_unit = models.CharField(max_length=256)
    subscription_data = models.JSONField(blank = True,null=True)
    created_by = models.CharField(max_length=256,verbose_name="Created By",default="chargebee")
    created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
    last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="chargebee")
    last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

    def __str__(self):
        return f"{self.id} - {self.sponsorship}"





# class SponsorApplication(models.Model):
#     sponsor = models.ForeignKey(Sponsor,on_delete = models.CASCADE)
#     application = models.ForeignKey(Application,on_delete=models.CASCADE)
#     start_date = models.DateField(null=True,blank=True)
#     status = models.CharField(max_length=256,null=True)
#     pledge_date = models.DateField(null=True)
#     is_active = models.BooleanField(default=True)
#     created_by = models.CharField(max_length=256,verbose_name="Created By")
#     created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
#     last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By")
#     last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

#     class Meta:
#         unique_together = ('sponsor', 'application',)

#     def __str__(self):
#         return f"{self.sponsor} - {self.application}"

class OtpMaster(models.Model):
    target = models.CharField(max_length=60)
    target_type = models.CharField(max_length=256)
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    otp = models.CharField(max_length=256)
    context = models.CharField(max_length=256)
    issued_count = models.IntegerField(default=1)
    is_verified = models.BooleanField(default=False)
    issued_date = models.DateTimeField(auto_now=True)
    expiry_date = models.DateTimeField()

    def __str__(self):
        return self.target


