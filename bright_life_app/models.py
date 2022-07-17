from enum import Enum
from re import M
from tkinter import CASCADE
from unittest.util import _MAX_LENGTH
from django.db import models
from django.forms import CharField
from django.utils import timezone
from django.core.validators import MinLengthValidator,MaxLengthValidator

# Create your models here.


class Kid(models.Model):
    name = models.CharField(max_length=100)
    birthday = models.DateField(help_text = 'Enter your birthday')
    age = models.IntegerField()
    email = models.EmailField(max_length=250)
    phone = models.IntegerField(validators = [MinLengthValidator(10),MaxLengthValidator(13)],unique=True,null=False)

    def __str__(self):
        return self.name



# class Country(models.Model):
#     name = models.CharField(max_length=256)
#     code = models.CharField(max_length=256,unique=True)
#     icon_url = models.CharField(max_length=256,blank=True)
#     is_active = models.BooleanField(default=True)
#     created_by = models.CharField(max_length=256)
#     created_date = models.DateTimeField(auto_now_add=True)
#     last_updated_by = models.CharField(max_length=256)
#     last_updated_date = models.DateTimeField(default=timezone)

#     def __str__(self):
#         return self.name



# class CountryState(models.Model):
#     name = models.CharField(max_length=256)
#     code = models.CharField(max_length=256,unique=True)
#     country_code = models.ForeignKey(Country,on_delete=CASCADE)
#     is_active = models.BooleanField(default=True)
#     created_by = models.CharField(max_length=256)
#     created_date = models.DateTimeField(auto_now_add=True)
#     last_updated_by = models.CharField(max_length=256)
#     last_updated_date = models.DateTimeField(default=timezone)

#     def __str__(self):
#         return self.name



# class Gender(Enum):
#         male = ('M', 'Male')
#         female = ('F', 'Female')
#         others = ('O', 'Others')
        
#         @classmethod
#         def get_value(cls, member):
#             return cls[member].value[0]
    

# class UserRole(Enum):
#     kid = ('child', 'Child')
#     sponsor = ('sponsor', 'Sponsor')
#     guardian = ('guardian', 'Guardian')

#     def get_value(cls,member):
#         return cls[member].value[0]


# class ChildStatus(Enum):
#     recieved = ('scholorship-received','ScholorshipReceived')
#     review = ('under-review','UnderReview')
#     waiting = ('waiting','Waiting')

#     def get_value(cls,member):
#         return cls[member].value[0]

# class ChildType(Enum):
#     orphan = ('orphan','Orphan')
#     withParents = ('with-parent','With Parent')

#     def get_value(cls,member):
#         return cls[member].value[0]



# class Child(models.Model):
#     name = models.CharField(max_length = 256)
#     birthday = models.DateField(blank = True, null = True)
#     email = models.EmailField()
#     mobile = models.CharField()
#     child_type = models.CharField(choices=[type.value for type in ChildType])
#     grade = models.CharField(max_length = 20,blank = True)
#     school_name = models.CharField(max_length = 250, blank = True)
#     school_address = models.ForeignKey(max_length = 256, null = True, blank = True)
#     hobbies = models.TextField(max_length = 20, blank = True,null = True)
#     aspirations = models.TextField(blank = True,null = True)
#     status = models.CharField(choices=[type.value for type in ChildStatus])
#     profile = models.ImageField(upload_to='img',blank=True)
    
#     def age(self):
#         import datetime
#         return int((datetime.datetime.now() - self.birthday).days / 365.25  )
#     age = property(age)

#     def __str__(self):
#         return self.name


# class DocumentType(Enum):
#     aadhar = ('aadhar','Aadhar')
#     pan = ('pan','Pan')
#     birth_certificate = ('birth-certificate','Birth Certificate')
#     ration_card = ('ration-card','Ration Card')
#     health_certificate = ('health-certificate','Health Certificate')
#     disability_certificate = ('disability','Disability Certificate')
#     admission_document = ('admission','Admission Document')
#     report_card = ('report_card','Report Card')

#     def get_value(cls,member):
#         return cls[member].value[0]



# class ChildDocument(models.Model):
#     name = models.CharField(max_length =256)
#     child_id = models.ForeignKey(Child)
#     document_type = models.CharField(choices=[type.value for type in DocumentType])
#     document_path = models.TextField()

#     def __str__(self):
#         return self.name

# class ChildAchievement(models.Model):
#     name = models.CharField(max_length =256)
#     child_id = models.ForeignKey(Child)
#     description = models.CharField(max_length = 256)
#     child_document_id = models.ForeignKey(ChildDocument)

#     def __str__(self):
#         return self.name


# class BankAccount(models.Model):
#     kid_id = models.ForeignKey(Kid)
#     bank_name = models.CharField(max_length = 256,null = True)
#     account_holder = models.CharField(max_length = 20, unique = True,null = True)
#     account_number = models.IntegerField()
#     branch = models.CharField(max_length = 256,null = True)
#     ifsc = models.CharField(max_length = 11,null = True)

#     def __str__(self):
#         return self.id