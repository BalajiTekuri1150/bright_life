from enum import Enum
from pickle import TRUE
from re import M
from tkinter import CASCADE
from unittest.util import _MAX_LENGTH
from django.db import models
from django.forms import CharField
from django.core.validators import MinLengthValidator,MaxLengthValidator
from django.utils.timezone import now
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import FileExtensionValidator

# Create your models here.






class Country(models.Model):
    name = models.CharField(max_length=256)
    code = models.CharField(max_length=256,unique=True)
    icon_url = models.CharField(max_length=256,blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name



class CountryState(models.Model):
    name = models.CharField(max_length=256)
    code = models.CharField(max_length=256,unique=True)
    country_code = models.ForeignKey(Country,on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name



class EnumGender(models.Model):
    name =models.CharField(max_length=256)
    gender = models.CharField(max_length=1)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name
    

class EnumUserRole(models.Model):
    role = models.CharField(max_length=256)
    name =models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.role




class EnumChildStatus(models.Model):
    name = models.CharField(max_length=256)
    status = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.status





class EnumChildType(models.Model):
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.type

class Child(models.Model):
    name = models.CharField(max_length = 256)
    birthday = models.DateField(null = True)
    email = models.EmailField(max_length=256)
    mobile = models.CharField(max_length=13)
    child_type =  models.ForeignKey(EnumChildType,on_delete=models.CASCADE)
    grade = models.CharField(max_length = 20,null = True)
    school_name = models.CharField(max_length = 250, null = True)
    school_address = models.CharField(max_length = 256, null = True)
    hobbies = models.TextField(max_length = 20,null = True)
    aspirations = models.TextField(null = True)
    status = models.ForeignKey(EnumChildStatus,on_delete=models.CASCADE,null=True)
    profile = models.ImageField(upload_to='img',null=True)
    
    def age(self):
        import datetime
        return int((datetime.datetime.now() - self.birthday).days / 365.25  )
    age = property(age)

    def __str__(self):
        return self.name

class KidDetails(models.Model):
    name = models.CharField(max_length=100)
    birthday = models.DateField(null=True,blank=True)
    age = models.IntegerField(blank=True)
    gender = models.ForeignKey(EnumGender,on_delete=models.CASCADE)
    email = models.EmailField(max_length=250,null=True,blank=True)
    mobile  = PhoneNumberField(unique = True,null = True,blank=True)
    profile = models.ImageField(upload_to='img',null=True,blank = True)
    child_type =  models.ForeignKey(EnumChildType,on_delete=models.CASCADE)
    grade = models.CharField(max_length = 20,null = True,blank = True)
    school = models.CharField(max_length = 250, null = True,blank=True)
    school_address = models.CharField(max_length = 256, null = True,blank=True)
    hobbies = models.TextField(max_length = 20,null = True,blank=True)
    aspirations = models.TextField(null = True,blank=True)
    status = models.ForeignKey(EnumChildStatus,on_delete=models.CASCADE,null=True)
    achievements = models.TextField(null=True,blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name


class GuardianDetails(models.Model):
    kid_id = models.ForeignKey(KidDetails,on_delete=models.CASCADE)
    profession = models.CharField(max_length=256,null=True,blank=True)
    annual_income = models.FloatField(null=True,blank=True)
    family_member = models.CharField(max_length=256,blank=True)
    extra_allowance = models.FloatField(null=True,blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name

class EnumDocumentType(models.Model):
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name


class ChildDocument(models.Model):
    name = models.CharField(max_length =256)
    child_id = models.ForeignKey(Child,on_delete=models.CASCADE)
    document_type = models.ForeignKey(EnumDocumentType,on_delete=models.CASCADE)
    document = models.FileField(upload_to='doc/' ,validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'img','png','jpeg'])])
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name

class ChildAchievement(models.Model):
    name = models.CharField(max_length =256)
    child_id = models.ForeignKey(Child,on_delete=models.CASCADE)
    description = models.CharField(max_length = 256)
    child_document_id = models.ForeignKey(ChildDocument,on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.name


class BankAccount(models.Model):
    kid_id = models.ForeignKey(KidDetails,on_delete=models.CASCADE)
    bank_name = models.CharField(max_length = 256,null = True,blank=True)
    state = models.CharField(max_length=256,null=True,blank=True)
    postal_code = models.PositiveIntegerField(validators = [MinLengthValidator(6),MaxLengthValidator(6)],null=True,blank=True)
    account_holder = models.CharField(max_length = 20, unique = True,null = True,blank=True)
    account_number = models.IntegerField(validators = [MinLengthValidator(9),MaxLengthValidator(18)],null=True,blank=True)
    branch = models.CharField(max_length = 256,null = True)
    ifsc = models.CharField(max_length = 11,null = True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=256)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.CharField(max_length=256)
    last_updated_date = models.DateTimeField(default=now)

    def __str__(self):
        return self.bank_name