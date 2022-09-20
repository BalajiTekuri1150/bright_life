
from locale import currency
from tkinter import CASCADE
from unittest.util import _MAX_LENGTH
from django.db import models
from django.core.validators import MinLengthValidator,MaxLengthValidator
from django.utils.timezone import now
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import FileExtensionValidator

from django.conf import settings

from rest_framework.authtoken.models import Token 
from .models import Application, User


class ChargebeeUser(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    customer_id =  models.CharField(max_length=40) # Chargebee customer id
    role = models.CharField(max_length=256,default='child')

    def __str__(self):
        return f"{self.id} - {self.customer_id} - {self.user}"

# class UserOrder(models.Model):
#     order_id = models.TextField(unique=True)
#     user = models.ForeignKey(User,on_delete=models.CASCADE)
#     purchaser_id = models.PositiveBigIntegerField()
#     gateway = models.CharField(max_length=256)
#     status = models.CharField(max_length=1)
#     start_time = models.DateTimeField()
#     end_time = models.DateTimeField(null=True,blank=True)
#     referrence_id = models.CharField(max_length=256,null=True,blank=True)
#     payment_source = models.TextField(null=True,blank=True)
#     country = models.TextField(null=True,blank=True)
#     state = models.TextField(null=True,blank=True)
#     city = models.TextField(null=True,blank=True)
#     payment_profile = models.PositiveIntegerField(null=True,blank=True)
#     created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
#     created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
#     last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
#     last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

#     def __str__(self):
#         return self.name


# class OrderAmountDetail(models.Model):
#     order_id = models.TextField()
#     order_amount = models.FloatField()
#     tax = models.FloatField()
#     total_amout = models.FloatField()
#     currency = models.CharField(max_length=256)
#     discount = models.FloatField(default=0)
#     created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
#     created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
#     last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
#     last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

#     def __str__(self):
#         return self.order_id


# class OrderFailure(models.Model):
#     order_id = models.TextField()
#     error_code = models.CharField(max_length=100)
#     error_message = models.CharField(max_length=500)
#     gateway = models.CharField(max_length=25)
#     created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
#     created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
#     last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
#     last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

#     def __str__(self):
#         return str(self.id)

# class OrderRecurrence(models.Model):
#     parent_order = models.TextField(unique=True)
#     status = models.CharField(max_length=256)
#     expiry_date = models.DateTimeField()
#     cancelled_date = models.DateTimeField(null=True,blank=True)
#     user_id = models.PositiveIntegerField()
#     # application = models.ForeignKey(Application,on_delete=models.CASCADE)
#     gateway = models.TextField()
#     recurring_token = models.TextField()
#     recurrence_count = models.PositiveIntegerField(default=0)
#     attributes = models.TextField(null=True,blank=True)
#     cancel_details = models.TextField(null=True,blank=True)
#     payment_profile_id = models.IntegerField(null=True,blank=True)

#     def __str__(self):
#         return str(self.id)   


# class OrderRecurrenceFailure(models.Model):
#     order_id = models.TextField()
#     parent_order_id = models.ForeignKey(OrderRecurrence,on_delete=models.CASCADE)
#     error_code = models.CharField(max_length=100)
#     error_message = models.CharField(max_length=500)
#     gateway = models.CharField(max_length=25)
#     is_active = models.BooleanField(default=True)
#     created_by = models.CharField(max_length=256,verbose_name="Created By",default="system")
#     created_date = models.DateTimeField(auto_now_add=True,verbose_name="Created Date")
#     last_updated_by = models.CharField(max_length=256,verbose_name="Last Updated By",default="system")
#     last_updated_date = models.DateTimeField(verbose_name="Updated Date",auto_now=True)

#     def __str__(self):
#         return str(self.id)

# class PaymentProfileInfo(models.Model):
#     user_id =models.IntegerField()
#     gateway = models.TextField()
#     customer_profile = models.TextField(null=True,blank=True)
#     payment_profile = models.TextField(null=True,blank=True)
#     card_detail = models.TextField(null=True,blank=True)
#     is_updatable = models.BooleanField(null=True,blank=True,default=False)
#     is_active = models.BooleanField(null=True,blank=True,default=False)
#     remember = models.BooleanField(null=True,blank=True)
#     card_type = models.TextField(null=True,blank=True)
#     unique_identifier = models.TextField(null=True,blank=True)
#     status = models.IntegerField(default=1)
#     last_used = models.DateTimeField(null=True,blank=True)
#     expiration_date = models.TextField(null=True,blank=True)


#     def __str__(self):
#         return str(self.id)



