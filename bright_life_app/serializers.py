from enum import unique
from unittest.util import _MAX_LENGTH
from django.forms import CharField
from pkg_resources import require
from rest_framework import serializers

from .models import Application, Country, CountryState, ApplicationDocument, EnumApplicationStatus, EnumChildType, EnumDocumentType, EnumGender, EnumUserRole, Guardian, Sponsor, Sponsorship, Sponsorship, SponsorshipPayment, User,BankDetails

from .payment_models import ChargebeeUser

from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework.authtoken.models import Token
from django.contrib.auth import password_validation
from django.utils.translation import gettext_lazy as _

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import AuthenticationFailed

from django.db import transaction, DatabaseError
from . import chargebee_utils as chargebee

from .logger import *



class RegisterSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())])
  password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
  password2 = serializers.CharField(write_only=True, required=True)
  class Meta:
    model = User
    fields = ('name', 'password', 'password2',
         'email', 'role')

  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs
  def create(self, validated_data):
    user = User.objects.create(
      name=validated_data['name'],
      email=validated_data['email'],
      role = validated_data['role'],
      is_email_verified = False
    )
    user.set_password(validated_data['password'])
    user.save()
    if user.role == "sponsor":
      try:
        sponsorProfile = Sponsor.objects.create(user_id=user.id,created_by=user.name,last_updated_by=user.name)
      except Exception as e:
        user.delete()
        return str(e)
    elif user.role == "guardian":
          try:
            guardianProfile = Guardian.objects.create(user_id=user.id,created_by=user.name,last_updated_by=user.name)
          except Exception as e:
            logger.exception(str(e))
            user.delete()
            return str(e)
    return user

class SignupSerializer(serializers.Serializer):
  email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())])
  password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
  password2 = serializers.CharField(write_only=True, required=True)
  otp = serializers.CharField()
  class Meta:
    fields = ('name', 'password', 'password2',
         'email', 'role','otp')

  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs
  def create(self, validated_data):
    logger.info("serializer method reached")
    user = User.objects.create(
      name=validated_data['name'],
      email=validated_data['email'],
      role = validated_data['role'],
      is_email_verified = True
    )
    user.set_password(validated_data['password'])
    user.save()
    if user.role == "sponsor":
      try:
        sponsorProfile = Sponsor.objects.create(user_id=user.id,created_by=user.name,last_updated_by=user.name)
      except Exception as e:
        user.delete()
        return str(e)
    return user





class SignupSerializer(serializers.Serializer):
  email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())])
  password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
  password2 = serializers.CharField(write_only=True, required=True)
  otp = serializers.CharField()
  class Meta:
    fields = ('name', 'password', 'password2',
         'email', 'role','otp')

  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs
  def create(self, validated_data):
    logger.info("serializer method reached")

    try:
      with transaction.atomic():
        user = User.objects.create(
        name=validated_data['name'],
        email=validated_data['email'],
        role = validated_data['role'],
        is_email_verified = True)
        # customer = chargebee.create_customer(validated_data)
        # logger.info("after creating chargebee account"+customer)
        # sub_data = ChargebeeUser.create(user=user, customer_id=customer.id)
        # logger.info("after creating Chargebee user"+sub_data)
        # if customer is None or user is None:
        #   logger.info("customer object :"+customer)
        #   logger.info("user object :"+user)
        #   raise DatabaseError
        user.set_password(validated_data['password'])
        user.save()
        if user.role == "sponsor":
          try:
            sponsorProfile = Sponsor.objects.create(user_id=user.id,created_by=user.name,last_updated_by=user.name)
          except Exception as e:
            logger.exception(str(e))
            user.delete()
            return str(e)
        elif user.role == "guardian":
          try:
            guardianProfile = Guardian.objects.create(user_id=user.id,created_by=user.name,last_updated_by=user.name)
          except Exception as e:
            logger.exception(str(e))
            user.delete()
            return str(e)
        return user
        # page = chargebee.create_checkout(customer, 'premium') # 'premium' is the plan id
        # sub_data.page_id = page.id
        # sub_data.save()
        # return redirect(page.url)
    except DatabaseError as e:
      logger.exception(str(e))
      return str(e)
    except Exception as e:
      logger.exception(str(e))
      return str(e)

    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=128)


# class ResetPasswordEmailRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField(min_length=2)

#     class Meta:
#         fields = ['email']

class OTPSerializer(serializers.Serializer):
  email = serializers.EmailField(min_length=2)
  context = serializers.CharField()

  class Meta:
    fields = ['email','context']

class VerifyOTPSerializer(serializers.Serializer):
  email = serializers.EmailField(min_length=2)
  context = serializers.CharField()
  otp = serializers.CharField()

  class Meta:
    fields = ['email','context','otp']

class UpdatePasswordSerializer(serializers.Serializer):
  email = serializers.EmailField(min_length=2)
  mobile = serializers.CharField(required = False)
  password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
  otp = serializers.CharField()

  class Meta:
    fields = ['email','password','otp']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password1 = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password2 = serializers.CharField(max_length=128, write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _('Old password did not match.Please enter a valid password')
            )
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': _("The two password fields didn't match.")})
        password_validation.validate_password(data['new_password1'], self.context['request'].user)
        return data

    def save(self, **kwargs):
        password = self.validated_data['new_password1']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user


class CountrySerializer(serializers.ModelSerializer):
  class Meta:
    model = Country
    # fields = ['id','name','code','icon_url']
    exclude = ['is_active','last_updated_by','last_updated_date','created_by','created_date']


  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class CountryStateSerializer(serializers.ModelSerializer):
  # country = CountrySerializer(read_only = True)
  class Meta:
    model = CountryState
    fields = ['id','name','code','country']
  
  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class GenderSerializer(serializers.ModelSerializer):
  class Meta:
    model = EnumGender
    fields = ['id','name','gender','description']

  
  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class UserRoleSerializer(serializers.ModelSerializer):
  class Meta:
    model = EnumUserRole
    fields = ['id','role','name','description']
  
  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class ChildStatusSerializer(serializers.ModelSerializer):
  class Meta:
    model = EnumApplicationStatus
    fields = ['id','name','status','description']
  
  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class ChildTypeSerializer(serializers.ModelSerializer):
  class Meta:
    model = EnumChildType
    fields = ['id','name','type','description']
  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class DocumentTypeSerializer(serializers.ModelSerializer):
  class Meta:
    model = EnumDocumentType
    exclude = ['is_active','last_updated_by','last_updated_date','created_by','created_date']


class SponsorProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = Sponsor
    fields = "__all__"

    # def get_or_create(self):
    #     defaults = self.validated_data.copy('id','user_id','first_name','last_name','mobile','organization','profile','source','address','city','state','country','postal_code')
    #     identifier = defaults.pop('user_id')
    #     return Sponsor.objects.get_or_create(unique_field=identifier, defaults=defaults)


class GuardianProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = Guardian
    fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = "__all__"


class ClientUserSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id','name','email','role']



class ClientSponsorProfle(serializers.ModelSerializer):
  user = ClientUserSerializer(read_only=True)
  class Meta:
    model = Sponsor
    fields = ['id','user','mobile','organization','profile','source','address','city','state','country','postal_code']

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}


class ClientGuardianProfle(serializers.ModelSerializer):
  user = ClientUserSerializer(read_only=True)
  class Meta:
    model = Guardian
    fields = ['id','user','mobile','organization','profile','source','address','city','state','country','postal_code']

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}      

  



# class ApplicationProfileSerializer(serializers.Serializer):
#   email = serializers.EmailField(
#   validators=[UniqueValidator(queryset=Application.objects.all())]
#   ,required=False)
#   name = serializers.CharField(max_length=256,required=False)
#   birthday = serializers.DateField(required=False)
#   child_type = serializers.CharField(max_length=256)
#   gender = serializers.CharField(max_length=256)
#   created_by = serializers.CharField(max_length=256)
#   last_updated_by = serializers.CharField(max_length=256)

#   def create(self,validated_data):
#     validated_data["child_type_id"] = EnumChildType.objects.filter(type=validated_data.pop("child_type")).first().id
#     validated_data["gender_id"] = EnumGender.objects.filter(gender=validated_data.pop("gender")).first().id
#     return Application.objects.create(**validated_data)

class ApplicationProfileSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(
  validators=[UniqueValidator(queryset=Application.objects.all())]
  ,required=False)
  class Meta:
    model = Application
    fields = ['email','name','birthday','child_type','gender','created_by','last_updated_by']

  def create(self,validated_data):
    validated_data["child_type_id"] = validated_data.pop("child_type")
    validated_data["gender_id"] = validated_data.pop("gender")
    return Application.objects.create(**validated_data)


  def update(self,instance,validated_data):
    instance.email = validated_data.get('email',instance.email)
    instance.name = validated_data.get('name',instance.name)
    instance.birthday = validated_data.get('birthday',instance.birthday)
    instance.child_type = validated_data.get('child_type',instance.child_type)
    instance.gender = validated_data.get('gender',instance.gender)
    instance.last_updated_by = validated_data.get('last_updated_by',instance.last_updated_by)
    instance.save()
    return instance


class EducationDetailsSerializer(serializers.Serializer):
  grade = serializers.CharField(required = False,max_length=256)
  school = serializers.CharField(required = False,max_length=256)
  school_address = serializers.CharField(required = False,max_length=256)
  hobbies = serializers.CharField(required = False)
  aspirations = serializers.CharField(required = False)
  achievements = serializers.CharField(required = False)
  last_updated_by = serializers.CharField(max_length=256)

  def update(self,instance,validated_data):
    instance.grade = validated_data.get('grade',instance.grade)
    instance.school =  validated_data.get('school_name',instance.school)
    instance.school_address =  validated_data.get('school_address',instance.school_address)
    instance.hobbies =  validated_data.get('hobbies',instance.hobbies)
    instance.aspirations =  validated_data.get('aspirations',instance.aspirations)
    instance.achievements =  validated_data.get('achievements',instance.achievements)
    instance.last_updated_by =  validated_data.get('last_updated_by',instance.last_updated_by)
    instance.save()
    return instance



class ApplicationSerializer(serializers.ModelSerializer):
  class Meta:
    model = Application
    fields = "__all__"
    write_only_fields = ['is_active','created_date','created_by','last_updated_date','last_updated_by']

  def create(self,validated_data):
    logger.info("validated_data :"+str(validated_data))
    validated_data["child_type_id"] = validated_data.pop("child_type")
    validated_data["gender_id"] = validated_data.pop("gender")
    return Application.objects.create(**validated_data)

  def update(self,instance,validated_data):
    instance.name = validated_data.get('name',instance.name)
    instance.birthday =  validated_data.get('birthday',instance.birthday)
    instance.age =  validated_data.get('age',instance.age)
    instance.gender =  validated_data.get('gender',instance.gender)
    instance.email =  validated_data.get('email',instance.email)
    instance.mobile =  validated_data.get('mobile',instance.mobile)
    instance.profile = validated_data.get('profile',instance.profile)
    instance.child_type =  validated_data.get('child_type',instance.child_type)
    instance.grade = validated_data.get('grade',instance.grade)
    instance.school =  validated_data.get('school',instance.school)
    instance.school_address =  validated_data.get('school_address',instance.school_address)
    instance.hobbies =  validated_data.get('hobbies',instance.hobbies)
    instance.aspirations =  validated_data.get('aspirations',instance.aspirations)
    instance.achievements =  validated_data.get('achievements',instance.achievements)
    instance.about =  validated_data.get('about',instance.about)
    instance.profession =  validated_data.get('profession',instance.profession)
    instance.zoho_id =  validated_data.get('zoho_id',instance.zoho_id)
    instance.annual_income =  validated_data.get('annual_income',instance.annual_income)
    instance.family_members =  validated_data.get('family_members',instance.family_members)
    instance.extra_allowance =  validated_data.get('extra_allowance',instance.extra_allowance)
    instance.last_updated_by =  validated_data.get('last_updated_by',instance.last_updated_by)
    instance.save()
    return instance

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}




class UpdateProfileSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(
  validators=[UniqueValidator(queryset=Application.objects.all())]
  )
  class Meta:
      model = Application
      fields = ['id','name','birthday','email','mobile','child_type','profile','last_updated_by']


class ClientBankDetailsSerializer(serializers.ModelSerializer):
  
  class Meta:
    model = BankDetails
    fields = ['id','application_id','bank_name','state','postal_code','account_holder' ,'account_number','branch','ifsc']

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}


class BankDetailsSerializer(serializers.ModelSerializer):

  class Meta:
    model = BankDetails
    # fields = "__all__"
    fields = ['id','application_id','bank_name','state','postal_code','account_number','account_holder','branch','ifsc','created_by','last_updated_by']


class ClientBankDetailSerializer(serializers.ModelSerializer):
  class Meta:
    model = BankDetails
    exclude = ['id','is_active','last_updated_by','last_updated_date','created_by','created_date']

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}
    
class ApplicationDocumentsSerializer(serializers.ModelSerializer):
  class Meta:
    model = ApplicationDocument
    fields = "__all__"

class ClientApplicationDocumentsSerializer(serializers.ModelSerializer):
  document_type = DocumentTypeSerializer(read_only = True)
  class Meta:
    model = ApplicationDocument
    fields = ['id','application_id','document_type','file_type','url','seq_no']
  
  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

class SponsorshipSerializer(serializers.ModelSerializer):
  class Meta:
    model = Sponsorship
    fields = "__all__"

  def create(self,validated_data):
    validated_data["sponsor_id"] = validated_data.pop("sponsor")
    validated_data["application_id"] = validated_data.pop("application")
    return Sponsorship.objects.create(**validated_data)

class ClientSponsorshipSerializer(serializers.ModelSerializer):
  class Meta:
    model = Sponsorship
    fields = ['id','sponsor_id','application_id','start_date','status','pledge_date']

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}

# newly added for chargebee details
class UpdateSponsorshipSerializer(serializers.ModelSerializer):
  class Meta:
    model = Sponsorship
    fields = ['id','sponsor_id','application_id','start_date','status','pledge_date','currency_code','amount','billing_period']

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}




class ApplicationDetailsSerializer(serializers.ModelSerializer):
  country = CountrySerializer(read_only=True)
  state = CountryStateSerializer(read_only = True)
  gender = GenderSerializer(read_only = True)
  child_type = ChildTypeSerializer(read_only = True)
  status = ChildStatusSerializer(read_only = True)
  guardian = ClientGuardianProfle(read_only=True)
  class Meta:
    model = Application
    fields = ["id","name","birthday","email","mobile","profile","country","state","grade","school","school_address","hobbies","aspirations","achievements","about","profession","annual_income","family_members","extra_allowance","gender","child_type","status","guardian","zoho_id"]

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}


class ChargebeeUserSerializer(serializers.ModelSerializer):
  class Meta:
    model = ChargebeeUser
    fields = ["role","user_id","customer_id"]


class SponsorshipPaymentSerializer(serializers.ModelSerializer):
  class Meta:
    model = SponsorshipPayment
    fields = "__all__"

class ClientSponsorshipPaymentSerializer(serializers.ModelSerializer):
  class Meta:
    model = SponsorshipPayment
    fields = ["sponsorship","reference_id","payment_date","currency","amount","next_billing_at","billing_period_unit","subscription_data"]

  def to_representation(self, instance):
    data = super().to_representation(instance)
    return {k: v for k, v in data.items() if v is not None and v != ""}
  

class CheckoutSerializer(serializers.Serializer):
    email = serializers.EmailField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    currency = serializers.CharField(max_length=3)
    is_recurring = serializers.BooleanField()
    plan_id = serializers.CharField(max_length=50)
    sponsorship_id = serializers.IntegerField()




