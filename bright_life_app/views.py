
from datetime import datetime, timedelta
from distutils.log import error
from email.mime import application
from inspect import modulesbyfile
import json
from logging import exception
from tkinter import FLAT
import traceback
from unittest import result
from urllib import response
from django.shortcuts import redirect, render

from requests import request

from .models import *
from django.db.models import Q
from django.contrib import messages
from django.core import serializers
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt 

from rest_framework.exceptions import APIException

from .serializers import ApplicationDetailsSerializer, ApplicationDocumentsSerializer, ChildStatusSerializer, ChildTypeSerializer, ClientGuardianProfle, ClientSponsorshipPaymentSerializer, ClientUserSerializer, DocumentTypeSerializer, GuardianProfileSerializer, RegisterSerializer,SponsorProfileSerializer,CountrySerializer,CountryStateSerializer,ApplicationProfileSerializer,EducationDetailsSerializer,ApplicationSerializer, SponsorshipPaymentSerializer, UpdateSponsorshipSerializer, UserRoleSerializer,GenderSerializer,BankDetailsSerializer,ClientBankDetailsSerializer,ClientSponsorProfle,ClientApplicationDocumentsSerializer, UserSerializer,LoginSerializer,SponsorshipSerializer,ClientSponsorshipSerializer,ChangePasswordSerializer,VerifyOTPSerializer,OTPSerializer,UpdatePasswordSerializer,SignupSerializer,ChargebeeUserSerializer

from django.db import IntegrityError


from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authtoken.models import Token
from rest_framework import generics
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny ,IsAuthenticated
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FileUploadParser
# from .utils import EmailSender
from .email import EmailSender
from .constants import OTPContext
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
from django.core.exceptions import ValidationError
import os
import random
from django.utils import timezone
import time

import boto3

from .logger import *

from django.db import transaction

from django.utils.timezone import get_current_timezone

import requests

import asyncio
import aiohttp

from django.utils.decorators import classonlymethod
from asgiref.sync import async_to_sync,sync_to_async
from django.core.cache import cache
from datetime import datetime, timedelta

import types
import stripe
import locale
from decimal import Decimal

# from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
# from dj_rest_auth.registration.views import SocialLoginView

# HTML email required stuff
# from django.core.mail import EmailMultiAlternatives
# from django.template.loader import render_to_string
# from django.utils.html import strip_tags

# class CustomRedirect(HttpResponsePermanentRedirect):

#     allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


# class GoogleSignup(SocialLoginView):
#     adapter_class = GoogleOAuth2Adapter

#     def post(self, request, *args, **kwargs):
#         # Call the parent post method to authenticate the user with Google
#         response = super().post(request, *args, **kwargs)

#         # If authentication was successful, create a new user account
#         if response.status_code == status.HTTP_200_OK:
#             user = response.data['user']
#             token = response.data['access_token']

#             # Customize the user object as needed
#             user.name = request.data.get('name')
#             user.email = request.data.get('email')
#             user.role = request.data.get('role')
#             user.save()

#             # Return the user object and token to the client
#             return Response({
#                 'user': user,
#                 'access_token': token
#             }, status=status.HTTP_200_OK)

#         # Otherwise, return the error response
#         return response



# class GoogleLogin(SocialLoginView):
#     adapter_class = GoogleOAuth2Adapter

#     def post(self, request, *args, **kwargs):
#         # Call the parent post method to authenticate the user with Google
#         response = super().post(request, *args, **kwargs)

#         # If authentication was successful, retrieve the user object and token
#         if response.status_code == status.HTTP_200_OK:
#             user = response.data['user']
#             token = response.data['access_token']

#             # Return the user object and token to the client
#             return Response({
#                 'user': user,
#                 'access_token': token
#             }, status=status.HTTP_200_OK)

#         # Otherwise, return the error response
#         return response


stripe.api_key = settings.STRIPE_SECRET_KEY

def format_price(price, currency):
    # Set the locale based on the currency
    if currency.lower() == 'usd':
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    elif currency.lower() == 'inr':
        locale.setlocale(locale.LC_ALL, 'en_IN.UTF-8')
    else:
        # Set a default locale for other currencies
        locale.setlocale(locale.LC_ALL, '')

    # Format the price based on the locale
    formatted_price = locale.currency(price, grouping=True)

    return formatted_price

class ListDonationPlans(APIView):
    permission_classes= [AllowAny]
    authentication_classes =[]
    def post(self,request):
        plans = stripe.Price.list(product=settings.STRIPE_PRODUCT_ID,
                                 active=True)
        logger.info("plans :"+str(plans))
        plan_data = []
        

        for plan in plans:
            amount_decimal = Decimal(plan.unit_amount_decimal)
            formatted_price = format_price(amount_decimal / 100, plan.currency)
            print(formatted_price)
            if plan.type == 'recurring':
                plan_data.append({
                    'id': plan.id,
                    'name': plan.nickname,
                    'amount': formatted_price,
                    'interval': plan.recurring.interval,
                    'currency': plan.currency,
                    "type" : plan.type
                })
            else :
               plan_data.append({
                    'id': plan.id,
                    'name': plan.nickname,
                    'currency': plan.currency,
                    'amount': formatted_price,
                    "type":plan.type
                }) 

        return Response({'plans': plan_data})
    
class CreateCheckoutSession(APIView):
    permission_classes= [AllowAny]
    authentication_classes =[]
    def post(self,request):
        sponsor_email = request.data.get('email')
        print(sponsor_email)
        amount = request.data.get('amount')
        print(amount)
        is_recurring = request.data.get('recurring') == 'true'
        currency = request.data.get('currency')

        # Create a one-time payment or recurring subscription
        if not is_recurring:
            session = stripe.checkout.Session.create(
                success_url='http://127.0.0.1:8000/success',
                cancel_url='http://127.0.0.1:8000/cancel',
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': currency,
                        'unit_amount': int(amount) * 100,  # Amount in cents
                        'product_data': {
                            'name': 'One-time Donation',
                            'description': 'Thank you for your support!',
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                customer_email=sponsor_email,
            )
        else:
            plan_id = request.data.get('plan_id')
            session = stripe.checkout.Session.create(
                success_url='http://127.0.0.1:8000/success',
                cancel_url='http://127.0.0.1:8000/cancel',
                payment_method_types=['card'],
                mode='subscription',
                subscription_data={
                    'items': [{
                        'plan': plan_id,
                    }],
                    'metadata': {
                        'email': sponsor_email,
                        'custom_amount': amount,
                    },
                },
                customer_email=sponsor_email,
            )
        logger.info("sessionId:"+str(session.id))
        print("sessionId:"+str(session.id))
        return Response({'sessionId': session.id})
    


class UpdateStripeSubscriptionDetails(APIView):
    def post(self,request):
        payload = request.body
        sig_header = request.META['HTTP_STRIPE_SIGNATURE']
        endpoint_secret = 'YOUR_STRIPE_WEBHOOK_SECRET'

        try:
            event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
            data = event['data']
            event_type = event['type']

            if event_type == 'payment_intent.succeeded':
                logger.info("payload :"+str(payload))
                # Payment succeeded, update payment status in the database
                payment_intent_id = data['object']['id']
                # Update the payment status in the database based on the payment_intent_id

            elif event_type == 'payment_intent.payment_failed':
                logger.info("payload :"+str(payload))
                # Payment failed, update payment status in the database
                payment_intent_id = data['object']['id']
                # Update the payment status in the database based on the payment_intent_id

            # Handle other event types as needed

            return Response({'status': 'success'})

        except ValueError as e:
            # Invalid payload
            return Response({'status': 'error', 'message': str(e)})

        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            return Response({'status': 'error', 'message': str(e)})



    



class RegisterUserAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

async def addDonorToZoho(user):
    url = 'https://zohoapis.in/crm/v2.1/Donors'
    data = {
        'data': [
            {
                'Name1': user.name,
                'Email': user.email
            }
        ]
    }
    token = get_access_token()
    logger.info("token :"+token)
    async with aiohttp.ClientSession(headers = {'Authorization': 'Zoho-oauthtoken '+token}) as session:
        async with session.post(url, json=data) as response:
            logger.info("response :"+response)
            if response.status == 401:
                error_response = await response.json()
                print(error_response)
                logger.error("error while syncing to zoho :"+str(error_response))
            else :
                logger.info("success response :"+str(response.json()))
                print("response :"+str(response.json()))


def addDonorToZohov1(user):
    url = 'https://zohoapis.in/crm/v2.1/Donors'
    data = {
        'data': [
            {
                'Name1': user.name,
                'Email': user.email
            }
        ]
    }
    token = get_access_token()
    logger.info("token :"+token)
    headers = {'Authorization': 'Zoho-oauthtoken '+token}
    zoho_response = requests.post(url,headers = headers, json=data)
    response = zoho_response.json()
    logger.info("response :"+str(response))
    if response['data'][0]['status'] == "success" :
        logger.info("success response :"+str(response))
        print("response :"+str(response))
        try:
            zoho_id = response['data'][0]['details']['id']
            print(zoho_id)
            print("is_sponsor_exists "+str(Sponsor.objects.filter(user=user).exists))
            sponsor = Sponsor.objects.filter(user=user).first()
            print(sponsor)
            if sponsor:
                sponsor.zoho_id = zoho_id
                sponsor.save()
            else :
                logger.error("no sponsor found with "+str(user)+"to update zoho_id :"+str(zoho_id))
        except Exception as e:
            logger.info("Exception while updating zoho_id to sponsor")
            logger.exception(str(e))
    else :
        error_response = response
        print(error_response)
        logger.error("error while syncing to zoho :"+str(error_response))

def updateDonortoZoho(donor):
    url = 'https://zohoapis.in/crm/v2.1/Donors'
    print("child :"+str(donor))
    if 'zoho_id' in donor and donor['zoho_id']:
        url = url+"/"+donor['zoho_id']
        filters={
            'data':[
                {
        
                }
            ]
        }
        if 'user' in donor and donor['user']:
            print(donor['user'])
            if 'name' in donor['user']:
                filters['data'][0]["Name1"]= donor['user']['name']
            if 'email' in donor['user'] :
                filters['data'][0]['Email'] = donor['user']['email']
        if 'mobile' in donor and donor['mobile']:
            filters['data'][0]["Donor_Mobile_Number"] = donor['mobile']
        if 'country' in donor and donor['country']:
            filters['data'][0]["Donor_Country"] = donor['country']
        if 'address' in donor and donor['address']:
            filters['data'][0]["Donor_Address"] = donor['address']
        print(filters)
        token = get_access_token()
        logger.info("token :"+token)
        headers = {'Authorization': 'Zoho-oauthtoken '+token}
        zoho_response = requests.put(url,headers = headers, json=filters)
        response = zoho_response.json()
        logger.info("response :"+str(response))
        if response['data'][0]['status'] == "success" :
            logger.info("success response :"+str(response))
            print("response :"+str(response))
        else :
            error_response = response
            print(error_response)
            logger.error("error while syncing to zoho :"+str(error_response))
    else :
        logger.error("zoho_id not found for donor"+str(donor['id']))




def addChildToZoho(child):
    url = 'https://zohoapis.in/crm/v2.1/Childs'
    print("child :"+str(child))
    filters={
        'data':[
        {
        
        }
        ]
        }
    if 'name' in child and child['name']:
        print(child['name'])
        filters['data'][0]["Name"]= child['name']
    if 'guardian' in child and child['guardian'] :
        if 'user' in child['guardian'] and child['guardian']['user'] :
            filters['data'][0]["Parent_Guardian_Name"] = child['guardian']['user']['name']
    if 'email' in child and child['email']:
        filters['data'][0]["Email"]= child['email']
    if 'mobile' in child and child['mobile']:
        filters['data'][0]["Mobile"] = child['mobile']
    if 'country' in child and child['country']:
        filters['data'][0]["Country"] = child.country['name']
    if 'school' in child and child['school']:
        filters['data'][0]["School"] = child['school']
    if 'school_address' in child and child['school_address']:
        filters['data'][0]["School_Address"] = child['school_address']
    if 'status' in child and child['status']:
        filters['data'][0]["Status"] = child['status']['name']
    if 'gender' in child and child['gender'] :
        filters['data'][0]["Gender"] = child['gender']['name']
    if 'region' in child and child['region']:
        filters['data'][0]["Address"] = child['region']
    if 'birthday' in child and child['birthday'] :
        filters['data'][0]["DOB"] = child['birthday']
    print(filters)
    token = get_access_token()
    logger.info("token :"+token)
    headers = {'Authorization': 'Zoho-oauthtoken '+token}
    zoho_response = requests.post(url,headers = headers, json=filters)
    response = zoho_response.json()
    logger.info("response :"+str(response))
    if response['data'][0]['status'] == "success" :
        logger.info("success response :"+str(response))
        print("response :"+str(response))
        try:
            zoho_id = response['data'][0]['details']['id']
            print(zoho_id)
            application = Application.objects.filter(id = child['id']).first()
            print(application)
            if application:
                application.zoho_id = zoho_id
                application.save()
            else :
                logger.error("no child found with "+str(application)+"to update zoho_id :"+str(zoho_id))
        except Exception as e:
            logger.info("Exception while updating zoho_id to child")
            logger.exception(str(e))
    else :
        error_response = response
        print(error_response)
        logger.error("error while syncing to zoho :"+str(error_response))


def updateChildtoZoho(child):
    url = 'https://zohoapis.in/crm/v2.1/Childs'
    print("child :"+str(child))
    if 'zoho_id' in child and child['zoho_id']:
        url = url+"/"+child['zoho_id']
        filters={
        'data':[
        {
        
        }
        ]
        }
        if 'name' in child and child['name']:
            print(child['name'])
            filters['data'][0]["Name"]= child['name']
        if 'guardian' in child and child['guardian'] :
            if 'user' in child['guardian'] and child['guardian']['user'] :
                filters['data'][0]["Parent_Guardian_Name"] = child['guardian']['user']['name']
        if 'email' in child and child['email']:
            filters['data'][0]["Email"]= child['email']
        if 'mobile' in child and child['mobile']:
            filters['data'][0]["Mobile"] = child['mobile']
        if 'country' in child and child['country']:
            filters['data'][0]["Country"] = child.country['name']
        if 'school' in child and child['school']:
            filters['data'][0]["School"] = child['school']
        if 'school_address' in child and child['school_address']:
            filters['data'][0]["School_Address"] = child['school_address']
        if 'status' in child and child['status']:
            filters['data'][0]["Status"] = child['status']['name']
        if 'gender' in child and child['gender'] :
            filters['data'][0]["Gender"] = child['gender']['name']
        if 'region' in child and child['region']:
            filters['data'][0]["Address"] = child['region']
        if 'birthday' in child and child['birthday'] :
            filters['data'][0]["DOB"] = child['birthday']
        print(filters)
        token = get_access_token()
        logger.info("token :"+token)
        headers = {'Authorization': 'Zoho-oauthtoken '+token}
        zoho_response = requests.put(url,headers = headers, json=filters)
        response = zoho_response.json()
        logger.info("response :"+str(response))
        if response['data'][0]['status'] == "success" :
            logger.info("success response :"+str(response))
            print("response :"+str(response))
        else :
            error_response = response
            print(error_response)
            logger.error("error while syncing to zoho :"+str(error_response))
    else :
        logger.error("zoho_id not found for child"+str(child['id']))


    
# class CreateView(APIView):
#     permission_classes= [AllowAny]
#     authentication_classes =[]
#     def post(self,request):

#         # async def retry_post():
#         #     await async_post()
#         async def async_post():
#             url = 'https://zohoapis.in/crm/v2.1/Donors'
#             print(url)
#             data = {
#                 'data': [
#                     {
#                         'Name1': "admin zoho",
#                         'Email': "admin@zoho.com"
#                 }
#                 ]
#             }
#             token = get_access_token()
#             print(token)
#             async with aiohttp.ClientSession(headers = {'Authorization': 'Zoho-oauthtoken '+token}) as session:
#                 print(session)
#                 print(get_access_token())
#                 async with session.post(url, json=data) as response:
#                     print(response)
#                     print(get_access_token())
#                     if response.status == 401:
#                         error_response = await response.json()
#                         print(error_response)
#                         # print(get_access_token())
#                         # await retry_post()
#                         # return Response({"response":error_response})
#                     else :
#                         return Response({"status":True})
#         return async_to_sync(async_post)()


# class CreateUserView(APIView):
#     permission_classes= [AllowAny]
#     authentication_classes =[]
#     async def async_post(self,request):
#             print(request)
#             logger.info(request)
#             try:
                
#                 if await User.objects.filter(email = request.data.get("email",None)).exists():
#                     return Response({"status":False,"error":"User already exists with the given email"})
#                 else :
#                     serializer = RegisterSerializer(data = request.data)
#                     data ={}
#                     if serializer.is_valid():
#                         user = await sync_to_async(serializer.create)(request.data)
#                         logger.info(user)
#                         if user.role == 'sponsor':
#                             print(user.role)
#                             asyncio.create_task(addDonorToZoho(user))
#                         data['message'] = "Successfully registered"
#                         data['email'] = user.email
#                         data['name'] = user.name
#                         data['id'] = user.id
#                         token = Token.objects.get(user=user).key
#                         data['token'] = token
#                         return Response({"status":True,"response":{"data":data}})
#                     else:
#                         logger.debug(serializer.errors)
#                         data = serializer.errors
#                     return Response({"status":False,"error":{"message":serializer.errors}})
#             except IntegrityError as e:
#                 logger.exception(str(e))
#                 raise ValidationError({"400": f'{str(e)}'})
#             except KeyError as e:
#                 logger.exception(str(e))
#                 raise ValidationError({"400": f'Field {str(e)} missing'})
#     async def post(self,request):
#         try:
#             response = await self.async_post(request)
#             return response
#         except Exception as e:
#             logger.exception(str(e))
#             return Response({"status": False, "error": {"message": str(e)}}) 
#     @classmethod
#     def as_view(cls, **kwargs):
#         view = super().as_view(**kwargs)
#         return async_view(view)
    
#     def async_view(func):
#         @types.coroutine
#         def wrapper(*args, **kwargs):
#             func = sync_to_async(func)
#             return await func(*args, **kwargs)
#         return wrapper


    
class CreateUserView(APIView):
    permission_classes= [AllowAny]
    authentication_classes =[]
    def post(self,request):
        logger.info(request)
        try:
            if User.objects.filter(email = request.data.get("email",None)).exists():
                return Response({"status":False,"error":"User already exists with the given email"})
            else :
                serializer = RegisterSerializer(data = request.data)
                data ={}
                if serializer.is_valid():
                    user = serializer.create(request.data)
                    logger.info(user)
                    data['message'] = "Successfully registered"
                    data['email'] = user.email
                    data['name'] = user.name
                    data['id'] = user.id
                    token = Token.objects.get(user=user).key
                    data['token'] = token
                    return Response({"status":True,"response":{"data":data}})
                else:
                    logger.debug(serializer.errors)
                    data = serializer.errors
                return Response({"status":False,"error":{"message":serializer.errors}})
        except IntegrityError as e:
            logger.exception(str(e))
            raise ValidationError({"400": f'{str(e)}'})
        except KeyError as e:
            logger.exception(str(e))
            raise ValidationError({"400": f'Field {str(e)} missing'})

class CheckEmail(APIView):
        permission_classes= [AllowAny]
        authentication_classes =[]
        def post(self,request):
            try :
                if User.objects.filter(email = request.data.get("email",None)).exists():
                    return Response({"status":False,"error":"User already exists with the given email"})
                else :
                    return Response({"status":True,"message":"No Account Exists with the given email"})
            except Exception as e:
                logger.exception(traceback.format_exc())
                logger.exception(str(e))
                # raise APIException
                return Response({"status":False,"error":{"message":str(e)}})

class OTPMandatorySignup(APIView):
    permission_classes= [AllowAny]
    authentication_classes =[]
    def post(self,request):
        try:
            if User.objects.filter(email = request.data.get("email",None)).exists():
                return Response({"status":False,"error":"User already exists with the given email"})
            else :
                serializer = SignupSerializer(data = request.data)
                data ={}
                if serializer.is_valid():
                    logger.info("serializer validated successfully"+str(serializer.data))
                    logger.info(serializer.data)
                    logger.info("serializer validated successfully")
                    email = serializer.data['email']
                    otp = serializer.data['otp']
                    # mobile = serializer.data['mobile']
                    context = 'signup'
                    if email:
                        target = email
                        target_type = "email"
                    else :
                        target = "mobile"
                        target_type = "mobile"
                    if verifyUpdateOTP(target,target_type,otp,context):
                        logger.info("OTP Verified Successfully")
                        logger.info("OTP Verified Successfully")
                        user = serializer.create(request.data)
                        if user.role == 'sponsor':
                            print(user.role)
                            addDonorToZohov1(user)
                        logger.info("OTP Verified Successfully"+str(user))
                        data['message'] = "Successfully registered a new user"
                        data['email'] = user.email
                        data['name'] = user.name
                        data['id'] = user.id
                        token = Token.objects.get(user=user).key
                        data['token'] = token
                        return Response({"status":True,"response":{"data":data}})
                    else :
                        logger.info("Invalid OTP or OTP Expired")
                        return Response({"status":False,"error":{"message":"Invalid OTP or OTP expired"}})
                else:
                    logger.debug(serializer.errors)
                    return Response({"status":False,"error":{"message":serializer.errors}})
        except IntegrityError as e:
            logger.exception(str(e))
            raise ValidationError({"400": f'{str(e)}'})
        except KeyError as e:
            logger.exception(str(e))
            raise ValidationError({"400": f'Field {str(e)} missing'})


class Login(APIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)
        try :
            if serializer.is_valid():
                email = serializer.data['email']
                password = serializer.data['password']
                if not User.objects.filter(email = email).exists():
                    logger.debug("Account doesn't exist with the given email :"+str(email))
                    return Response({"status":False,"message":"Account doesn't exist with the given email"})
                else :
                    user = authenticate(email=email, password=password)
                    if user:
                        if user.is_active:
                            token, created = Token.objects.get_or_create(user=user)
                            userObj = ClientUserSerializer(user)
                            logger.info(userObj.data)
                            role = userObj.data['role']
                            user_id = userObj.data['id']
                            if role == "sponsor" :
                                if Sponsor.objects.filter(user = user_id,is_active = True).exists():
                                    logger.info("sponsor exists")
                                    sponsor_profile = Sponsor.objects.get(user = user_id)
                                    logger.info(sponsor_profile)
                                    serializer = ClientSponsorProfle(sponsor_profile)
                                    return Response({'status':True,'response':{'user':userObj.data,'sponsor' :serializer.data},'token': token.key},
                                                status=status.HTTP_200_OK)
                                else :
                                    return Response({'status':True,'response':{'user':userObj.data},'token': token.key},
                                                status=status.HTTP_200_OK)
                            elif role == "guardian" :
                                if Guardian.objects.filter(user = user_id,is_active = True).exists():
                                    guardian_profile = Guardian.objects.get(user = user_id,)
                                    logger.info(guardian_profile)
                                    serializer = ClientGuardianProfle(guardian_profile)
                                    return Response({'status':True,'response':{'user':userObj.data,'guardian':serializer.data},'token': token.key},
                                            status=status.HTTP_200_OK)
                                else :
                                    return Response({'status':True,'response':{'user':userObj.data},'token': token.key},
                                            status=status.HTTP_200_OK)
                            else :
                                return Response({'status':True,'response':{'user':userObj.data},'token': token.key},
                                            status=status.HTTP_200_OK)
                        else:
                            logger.debug("User account not active"+str(user))
                            content = {'status':False,"error":{'message': 'User account not active.'}}
                            return Response(content,
                                            status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        logger.debug("Invalid Password "+str(serializer.data))
                        content = {'status':False,"error":{'message':'Invalid Password'}}
                        return Response(content, status=status.HTTP_401_UNAUTHORIZED)
            else:
                logger.exception(serializer.errors)
                return Response({"status":False,"error":{"message":serializer.errors}},
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})

class ChangePassword(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = self.request.data
        logger.info("ChangePassword initiated")
        try :
            serializer = ChangePasswordSerializer(data = data,context={'request': request})
            if serializer.is_valid():
                serializer.save()
                logger.info("Password Updated Successfully")
                return Response({"status":True,"response":{"message":"Password Updated Successfully"}})
            else :
                logger.debug(serializer.errors)
                return Response({"status":False,"error":{"message":serializer.errors}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})




def generateOTP():
    return str(random.randint(1000,9999))
    

def sendOTP(email,context,user):
    otp = generateOTP()
    logger.info("generated OTP :"+otp)
    if context == "forgot_password":
        message = "Dear "+user.name+"\n Use below OTP to reset you BrightLife Account Password \n OTP :"+str(otp)
        subject = "Reset your BrightLife Account Password"
        data = {'subject':subject,'email_body': message, 'to_email': email}
    else :
        message = "Dear User \n Use below OTP to verify your account \n OTP :"+str(otp)
        subject = "Verify your Account"
        data = {'subject':subject,'email_body': message, 'to_email': email}
    # user = User.objects.filter(email = email)
    try :
        status = EmailSender.send_email(data)
        logger.info("Email Status "+str(status))
        if status > 0:
            expiry_time = datetime.now() + timedelta(minutes = 20)
            current_time = datetime.now()
            oldDetails = OtpMaster.objects.filter(target = email,context = context,expiry_date__gte = current_time).exclude(is_verified = True).first()
            logger.info("oldDetails"+str(oldDetails))
            if oldDetails:
                logger.info("otp :"+str(otp))
                maxAttempts = 20
                if (oldDetails.issued_count < maxAttempts):
                    OtpMaster.objects.filter(id = oldDetails.id).update(issued_date = current_time, expiry_date=expiry_time,otp = otp,issued_count =oldDetails.issued_count+1)
                    return oldDetails.id
                else :
                    logger.info("OTP Resend max attempts limit exceeded : "+str(maxAttempts))
                    return None
            else :
                logger.info(otp)
                OtpMaster.objects.create(target = email,target_type = "email",context= context,otp = otp,expiry_date = expiry_time) 
                logger.info("Referrence Id : "+str(OtpMaster.objects.last().id))
            return OtpMaster.objects.last().id
        else :
            logger.info("Unable to send email ")
            return False
    except Exception as e:
        logger.exception(traceback.format_exc())
        logger.exception(str(e))
        # raise APIException
        return Response({"status":False,"error":{"message":str(e)}})

def sendSignupOTP(email,context):
    otp = generateOTP()
    logger.info("generated otp :"+str(otp))
    message = "Dear User \n Use below OTP to verify your account \n OTP :"+str(otp)
    subject = "Verify your Account"
    data = {'subject':subject,'email_body': message, 'to_email': email}
    logger.info("Signup OTP request :"+str(data))
    try :
        status = EmailSender.send_email(data)
        logger.info("Email sent status:"+str(status))
        if status > 0:
            expiry_time = timezone.now() + timedelta(minutes = 20)
            current_time = timezone.now()
            logger.info("current_time :"+str(current_time))
            logger.info("expiry_time :"+str(expiry_time))
            oldDetails = OtpMaster.objects.filter(target = email,context = context,expiry_date__gte = current_time).exclude(is_verified = True).last()
            if oldDetails:
                logger.info("Old Details :"+str(oldDetails))
                logger.info(oldDetails.id)
                maxAttempts = 100
                if (oldDetails.issued_count < maxAttempts):
                    OtpMaster.objects.filter(id = oldDetails.id).update(issued_date = current_time, expiry_date=expiry_time,otp = otp,issued_count =oldDetails.issued_count+1)
                    return oldDetails.id
                else :
                    logger.info("Signup resend OTP max limit exceeded :"+maxAttempts)
                    return None
            else :
                logger.info("otp :"+str(otp))
                logger.info("otp :"+str(otp))
                OtpMaster.objects.create(target = email,target_type = "email",context= context,otp = otp,expiry_date = expiry_time) 
                logger.info(OtpMaster.objects.last().id)
                logger.info(OtpMaster.objects.last().id)
            return OtpMaster.objects.last().id
        else :
            logger.debug("Error while sending signup otp")
            return False
    except Exception as e:
        logger.exception(traceback.format_exc())
        logger.exception(str(e))
        # raise APIException
        return Response({"status":False,"error":{"message":str(e)}})

class GetOTP(APIView):
    permission_classes = (AllowAny,)
    def post(self,request):
        logger.info("get OTP request : "+str(request.data))
        serializer = OTPSerializer(data = request.data)
        try :
            if serializer.is_valid():
                email = serializer.data['email']
                context = serializer.data['context']
                if User.objects.filter(email=email).exists() :
                    user = User.objects.get(email=email)
                    if (context == "signup" or context == "forgot_password"):
                        try:
                            referrence_id = sendOTP(email,context,user)
                            if referrence_id:
                                return Response({"status":True,"message":"OTP Sent Successfully","referrence_id":referrence_id})
                            else :
                                return Response({"status":False,"message":"OTP Limited exceeded"},status =status.HTTP_429_TOO_MANY_REQUESTS)
                        except Exception as e:
                            logger.exception(str(e))
                            # raise APIException
                            return Response({"status":False,"message":str(e)},status = status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else :
                        logger.debug("Invalid Context :"+context)
                        return Response({"status":False,"message":"Invalid context"})
                else :
                    logger.info("Invalid Account :"+email)
                    return Response({"status":False,"message":"Invalid Account"})
            else :
                logger.exception(str(e))
                return Response({"status":False,"message":serializer.errors})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})

class GetOTPV2(APIView):
    permission_classes = (AllowAny,)
    def post(self,request):
        serializer = OTPSerializer(data = request.data)
        try :
            if serializer.is_valid():
                email = serializer.data['email']
                context = serializer.data['context']
                if context == "signup":
                    logger.info("Email :"+email)
                    logger.info(email)
                    if not User.objects.filter(email = email).exists():
                        try:
                            referrence_id = sendSignupOTP(email,context)
                            if referrence_id:
                                logger.info("referrence id :"+str(referrence_id))
                                return Response({"status":True,"response":{'message':"OTP Sent Successfully","referrence_id":referrence_id}})
                            else :
                                logger.debug("Error while sending OTP")
                                return Response({"status":False,"response":{"message":"Error while sending OTP"}},status =status.HTTP_429_TOO_MANY_REQUESTS)
                        except Exception as e:
                            logger.exception(str(e))
                            logger.info(e)
                            # raise APIException
                            return Response({"status":False,"message":str(e)},status = status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else :
                        return Response({"status":False,"error":{"message":"User already Exists"}})
                elif context == "forgot_password" :
                    if User.objects.filter(email=email).exists() :
                        user = User.objects.get(email=email)
                        try:
                            referrence_id = sendOTP(email,context,user)
                            logger.info(referrence_id)
                            if referrence_id:
                                logger.info("Reference id "+str(referrence_id))
                                return Response({"status":True,"response":{"message":"OTP Sent Successfully","referrence_id":referrence_id}})
                            else :
                                return Response({"status":False,"error":{"message":"OTP Limited exceeded"}},status =status.HTTP_429_TOO_MANY_REQUESTS)
                        except Exception as e:
                            logger.exception(str(e))
                            raise APIException
                            # return Response({"status":False,"message":str(e)},status = status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else :
                        logger.debug("Invalid email :"+email)
                        return Response({"status":False,"error":{"message":"Invalid Account"}})
                else :
                    logger.debug("Invalid Context")
                    return Response({"status":False,"error":{"message":"invalid context"}})
            else :
                logger.exception(str(e))
                return Response({"status":False,"error":{"message":serializer.errors}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})


class ResendOTP(APIView):
    permission_classes = [AllowAny,]

    def post(self,request):
        # email = request.data['email']
        # user = User.objects.get(email = email)
        current_time = timezone.now()
        expiry_time = timezone.now()+timedelta(minutes = 15)
        logger.info("Current Time "+str(current_time))
        logger.info("expiry time :"+str(expiry_time))
        referrence_id = request.data["referrence_id"]
        OTPDetails = OtpMaster.objects.get(id = referrence_id,expiry_date__gte = current_time)
        try :
            if OTPDetails:
                email = OTPDetails.target
                if OTPDetails.is_verified:
                    logger.debug("Invalid referrence id for resend :"+referrence_id)
                    return Response({"status":False,"error":{"message ":"ErrorOTPInvalidReferenceForResend"}})
                elif OTPDetails.expiry_date < current_time :
                    otp = generateOTP()
                    message = "Use below OTP to reset you BrightLife Account Password \n OTP :"+otp
                    subject = "Reset your BrightLife Account Password"
                    data = {'subject':subject,'email_body': message, 'to_email': OTPDetails.target}
                    status =EmailSender.send_email(data)
                    if status > 0:
                        OtpMaster.objects.get(id = referrence_id).update(expiry_date=expiry_time,otp = otp,issued_count = OTPDetails.issued_count+1)
                        logger.info("referrence id "+str(referrence_id))
                        return Response({"status":True,"response":{"message":"OTP sent successfully","reference_id":referrence_id}})
                    else :
                        return Response({"status":False,"error":{"message":"error while sending email"}})
                else :
                    otp= generateOTP()
                    logger.info("context : "+OTPDetails.context)
                    logger.info(OTPDetails.context)
                    if OTPDetails.context == "signup":
                        message = "Dear User \n Use below OTP to verify your account \n OTP :"+str(otp)
                        subject = "Verify your Account"
                        data = {'subject':subject,'email_body': message, 'to_email': email}
                    else :
                        # user = User.objects.get(id = request.user.id)
                        # logger.info("User : "+str(user))
                        # print(user)
                        # message = "Hello "+user.name+"\n Use below OTP to reset you BrightLife Account Password \n OTP :"+otp
                        message = "Use below OTP to reset you BrightLife Account Password \n OTP :"+otp
                        subject = "Reset your BrightLife Account Password"
                        data = {'subject':subject,'email_body': message, 'to_email': OTPDetails.target}
                    status =EmailSender.send_email(data)
                    if status > 0:
                        OtpMaster.objects.filter(id = referrence_id).update(expiry_date=expiry_time,otp = otp,issued_count =OTPDetails.issued_count+1)
                        logger.info("referrence id : "+str(referrence_id))
                        return Response({"status":True,"response":{"message":"OTP Sent Successfully","referrence_id":referrence_id}})
                    else :
                        return Response({"status":False,"error":{"message":"error while sending email"}})
                    
            else :
                logger.error("Invalid referrence for resend")
                return Response({"status":False,"message ":"ErrorOTPInvalidReferenceForResend"})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})



class ResendOTPV2(APIView):
    permission_classes = [AllowAny,]

    def post(self,request):
        current_time = timezone.now()
        expiry_time = timezone.now()+timedelta(minutes = 15)
        referrence_id = request.data.get("referrence_id")
        try :
            if referrence_id:
                logger.info("current time : "+str(current_time))
                logger.info("expiry_time : "+str(expiry_time))
                logger.info("referrence id :"+str(referrence_id))
                OTPDetails = OtpMaster.objects.filter(pk = referrence_id,expiry_date__gte = current_time).last()
                if OTPDetails:
                    email = OTPDetails.target
                    logger.info("user id : "+str(OTPDetails.user_id))
                    logger.info("email : "+str(email))
                    logger.info(OTPDetails.user_id)
                    logger.info(email)
                    logger.info(OTPDetails.is_verified)
                    if OTPDetails.is_verified:
                        logger.info("Invalid referrence for resend OTP")
                        return Response({"status":False,"error":{"message ":"ErrorOTPInvalidReferenceForResend"}})
                    elif not OTPDetails.issued_count < 20:
                        logger.info("Error OTP issued count limit exceeded")
                        return Response({"status" :False,"error":{"message":"ErrorOTPLimitExceeded"}})
                    # elif OTPDetails.expiry_date < current_time :
                    else :
                        otp = generateOTP()
                        logger.info("context : "+OTPDetails.context)
                        if OTPDetails.context == "signup":
                            message = "Dear User \n Use below OTP to verify your account \n OTP :"+str(otp)
                            subject = "Verify your Account"
                            data = {'subject':subject,'email_body': message, 'to_email': email}
                        else :
                            # user = User.objects.get(id = request.user.id)
                            # logger.info("User : "+str(user))
                            # print(user)
                            # message = "Hello "+user.name+"\n Use below OTP to reset you BrightLife Account Password \n OTP :"+otp
                            message = "Use below OTP to reset you BrightLife Account Password \n OTP :"+otp
                            subject = "Reset your BrightLife Account Password"
                            data = {'subject':subject,'email_body': message, 'to_email': OTPDetails.target}
                        status =EmailSender.send_email(data)
                        if status > 0:
                            OtpMaster.objects.filter(id = referrence_id).update(expiry_date=expiry_time,otp = otp,issued_count = OTPDetails.issued_count+1)
                            logger.info("referrence id : "+str(referrence_id))
                            return Response({"status":True,"response":{"message":"OTP Sent Successfully","referrence_id":referrence_id}})
                        else :
                            return Response({"status":False,"error":{"message":"Error while sending email"}})
                else :
                    logger.info("ErrorOTPInvalidReferenceForResend OTP")
                    return Response({"status":False,"error":{"message ":"ErrorOTPInvalidReferenceForResend"}})
            else :
                logger.info("Missing field referrence_id")
                return Response({"status":False,"error":{"message ":"missing field referrence_id","details":request.data}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})


def verifyUpdateOTP(target,target_type,otp,context):
    latestOTP = OtpMaster.objects.filter(target = target,target_type = target_type, context = context,is_verified = False).last()
    if not latestOTP:
        return False
    # elif context == "signup" :
    else:
        if latestOTP.otp == otp and latestOTP.expiry_date > timezone.now() and latestOTP.is_verified == False:
            latestOTP.is_verified = True
            latestOTP.save()
            return True
        else :
            return False
    # else:
    #     if latestOTP.otp == otp and latestOTP.expiry_date > timezone.now() and latestOTP.is_verified == False:
    #         return True
    #     else :
    #         return False

class UpdatePassword(APIView):
    permission_classes = [AllowAny,]

    def post(self,request):
        serializer = UpdatePasswordSerializer(data = request.data)
        try :
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']
                password = request.data['password']
                context = 'forgot_password'
                if email:
                    target = email
                    target_type = "email"
                    user = User.objects.get(email = target)
                else :
                    target = "mobile"
                    target_type = "mobile"
                    user = User.objects.get(mobile = target)
                if verifyUpdateOTP(target,target_type,otp,context):
                    user.set_password(password)
                    user.save()
                    logger.info("Password updated successfully")
                    return Response({"status":True,"response":{"message":"Password Updated Successfully"}})
                else :
                    return Response({"status":False,"error":{"message":"Invalid OTP or OTP expired"}})

            else :
                logger.debug(str(serializer.errors))
                return Response({"status":False,"error":{"message" :serializer.errors}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})




class verifyOTP(APIView):
    permission_classes = [AllowAny,]
    def post(self,request):
        try :
            data = request.data
            serializer = VerifyOTPSerializer(data = data)
            logger.info(serializer)
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']
                context = serializer.data['context']
                latestOTP = OtpMaster.objects.filter(target = email,context = context).last()
                if not latestOTP:
                    logger.info("No matching latest otp found for the given target :"+email)
                    return Response({"status":False,"error":{"message":"Invalid OTP"}})
                else :
                    if latestOTP.otp == otp and latestOTP.expiry_date > timezone.now() and latestOTP.is_verified == False:
                        logger.info("OTP Verification successfull")
                        return Response({"status":True,"response":{"message":"OTP verified successfully"}})
                    else :
                        logger.error("Invalid OTP")
                        return Response({"status":False,"error":{"message":"Invalid otp or OTP expired"}})
            else :
                logger.error(serializer.errors)
                return Response({"status":False,"error":{"message":serializer.errors}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})



class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self,request):
        request.user.auth_token.delete()
        return Response({"status":True,"response":{"message":"Logout Successful"}})

class UpdateSponsorProfile(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self,request):
        data = request.data.copy()
        logger.info("Sponsor object :"+str(data))
        id = data.get("id")
        try:
            if id:
                if Sponsor.objects.filter(id=id).exists():
                    instance = Sponsor.objects.get(id = id)
                    data['created_by'] = instance.created_by
                    data['last_updated_by'] = request.user.name
                    data['is_active'] = True
                    userObj = data.pop('user')
                    logger.info("user object :"+str(userObj))
                    user = json.loads(userObj[0])
                    data['user']= user.get('id')
                    userInstance = User.objects.get(pk =user.get('id'))
                    userInstance.email = user.get('email',userInstance.email)
                    userInstance.name = user.get('name',userInstance.name)
                    userInstance.last_updated_by = request.user.name
                    serializer = SponsorProfileSerializer(instance,data=data)
                    if serializer.is_valid() :
                        try:
                            userInstance.save()
                            serializer.save()
                            sponsor = Sponsor.objects.get(pk = data.get('id'))
                            res = ClientSponsorProfle(sponsor)
                            updateDonortoZoho(res)
                            logger.info(res.data)
                            return Response({"status":True,"response":{"data":res.data}})
                        except Exception as e:
                            logger.exception(traceback.format_exc())
                            logger.exception(str(e))
                            # raise APIException
                            Response({"status":False,"error":{"message":str(e)}})
                    return Response({"status":False,"error":{"message":serializer.errors}})
                else :
                    return Response({"status ":False,"error": "No Such Sponsor found with id :"+str(id)})
            else :
                return Response({"status":False,"error":"id field is required"})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            Response({"status":False,"error":{"message":str(e)}})


class UpdateSponsorDetails(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self,request):
        try:
            data = request.data
            id = data.get("id")
            if id:
                if Sponsor.objects.filter(id=id).exists():
                    instance = Sponsor.objects.get(id = id)
                    sponsorData = ClientSponsorProfle(instance)
                    data['created_by'] = instance.created_by
                    data['last_updated_by'] = request.user.name
                    logger.info("instance"+str(sponsorData.data))
                    logger.info(sponsorData.data['user']['id'])
                    data['user'] = sponsorData.data['user']['id']
                    serializer = SponsorProfileSerializer(instance,data=data)
                    if serializer.is_valid() :
                        try:
                            serializer.save()
                            sponsor = Sponsor.objects.get(pk = data.get('id'))
                            res = ClientSponsorProfle(sponsor)
                            logger.info(res.data)
                            return Response({"status":True,"response":{"data":res.data}})
                        except Exception as e:
                            logger.exception(str(e))
                            # raise APIException
                            Response({"status":False,"error":{"message":str(e)}})
                    return Response({"status":False,"error":{"message":serializer.errors}})
                else :
                    return Response({"status ":False,"error": "No Such Sponsor found with id :"+str(id)})
            else :
                return Response({"status":False,"error":"id field is required"})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            Response({"status":False,"error":{"message":str(e)}})



class UpdateGuardianProfile(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self,request):
        data = request.data.copy()
        id = data.get("id")
        try :
            if id:
                if Guardian.objects.filter(id=id).exists():
                    instance = Guardian.objects.get(id = id)
                    data['created_by'] = instance.created_by
                    data['last_updated_by'] = request.user.name
                    data['is_active'] = True
                    userObj = data.pop('user')
                    logger.info("user object :"+str(userObj))
                    user = json.loads(userObj[0])
                    data['user']= user.get('id')
                    # user = data.pop('user')
                    # data['user']= user.get('id')
                    userInstance = User.objects.get(pk =user.get('id'))
                    userInstance.email = user.get('email',userInstance.email)
                    userInstance.name = user.get('name',userInstance.name)
                    userInstance.last_updated_by = request.user.name
                    serializer = GuardianProfileSerializer(instance,data=data)
                    if serializer.is_valid() :
                        try:
                            userInstance.save()
                            serializer.save()
                            sponsor = Guardian.objects.get(pk = data.get('id'))
                            res = ClientGuardianProfle(sponsor)
                            logger.info(res.data)
                            return Response({"status":True,"response":{"data":res.data}})
                        except Exception as e:
                            logger.exception(str(e))
                            # raise APIException
                            Response({"status":False,"error":{"message":str(e)}})
                    return Response({"status":False,"error":{"message":serializer.errors}})
                else :
                    return Response({"status ":False,"error": "No Such Guardian found with id :"+str(id)})
            else :
                return Response({"status":False,"error":"id field is required"})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})



        
class getSponsorProfileView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        if Sponsor.objects.filter(user = request.GET.get("user_id"),is_active = True).exists():
            sponsor_profile = Sponsor.objects.get(user = request.GET.get("user_id"))
            logger.info(sponsor_profile)
            serializer = ClientSponsorProfle(sponsor_profile)
            serializeddata = serializer.data
            logger.info("serializeddata"+str(serializeddata))
            try :
                profile =serializer.data.get('profile',None)
                if profile :
                    logger.info("profile :"+str(profile))
                    serializeddata['profile'] = profile.replace("https://yuppeducational-images.s3.amazonaws.com","https://d28rlmk1ou6g18.cloudfront.net")
                    return Response({"status":True,"response":{"sponsor":serializeddata}})
                else :
                    return Response({"status":True,"response":{"sponsor":serializer.data}})
            except Exception as e:
                logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})
        else :
            return Response({"status":False,"error":{"message":"Sponsor Details not found"}})

class getGuardianProfileView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        if Guardian.objects.filter(user = request.GET.get("user_id"),is_active = True).exists():
            guardian_profile = Guardian.objects.get(user = request.GET.get("user_id"))
            logger.info(guardian_profile)
            serializer = ClientGuardianProfle(guardian_profile)
            serializeddata = serializer.data
            logger.info("serializeddata"+str(serializeddata))
            try :
                profile =serializer.data.get('profile',None)
                if profile :
                    logger.info("profile :"+str(profile))
                    serializeddata['profile'] = profile.replace("https://yuppeducational-images.s3.amazonaws.com","https://d28rlmk1ou6g18.cloudfront.net")
                    return Response({"status":True,"response":{"guardian":serializeddata}})
                else :
                    return Response({"status":True,"response":{"guardian":serializer.data}})
            except Exception as e:
                logger.exception(str(e))
            # return Response({"status":True,"response":{"guardian":serializer.data}})
        else :
            return Response({"status":False,"error":{"message":"Guardian Details not found"}})
       
    



class CountryList(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        countries = Country.objects.filter(is_active = True)
        serializer = CountrySerializer(countries,many=True)
        return Response({"status":True,"response":{"data":serializer.data}})


class GetCountryState(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        country_id = self.request.GET.get('country_id',None)
        data ={}
        if country_id:
            states = CountryState.objects.filter(country_id=country_id,is_active = True)
            serializer = CountryStateSerializer(states,many=True)
            # data['status'] = True
            # data['response'] = serializer.data
            return Response({"status":True,"response":{"data":serializer.data}})
        return Response({"status":False,"error":{"message":"Missing parameter country_id"}})

class ListGender(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        genderList = EnumGender.objects.filter(is_active = True)
        serializer = GenderSerializer(genderList,many=True)
        return Response({"status":True,"response":{"data":serializer.data}})

class ListRoles(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        rolesList = EnumUserRole.objects.filter(is_active = True)
        serializer = UserRoleSerializer(rolesList,many=True)
        return Response({"status":True,"response":{"data":serializer.data}})

class ListChildStatus(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        childStatus = EnumApplicationStatus.objects.filter(is_active = True)
        serializer = ChildStatusSerializer(childStatus,many = True)
        return Response({"status":True,"response":{"data":serializer.data}})

class ListChildType(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        childType = EnumChildType.objects.filter(is_active = True)
        serializer = ChildTypeSerializer(childType,many=True)
        return Response({"status":True,"response":{"data":serializer.data}})

class ListDocumentTypes(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        documentType = EnumDocumentType.objects.filter(is_active = True)
        serializer = DocumentTypeSerializer(documentType,many=True)
        return Response({"status":True,"response":{"data":serializer.data}})



class MyPaginator(PageNumberPagination):
    page_size = 5
    page_size_query_param = 'page_size'
    max_page_size = 1000

class getApplicationDetails(APIView,MyPaginator):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        filters={}
        application_id = self.request.GET.get("application_id",None)
        email = self.request.GET.get("email",None)
        search = self.request.GET.get("search",None)
        state = self.request.GET.get("state",None)
        country = self.request.GET.get("country",None)
        region = self.request.GET.get("region",None)
        gender = self.request.GET.get("gender",None)
        child_type = self.request.GET.get("child_type",None)
        guardian = self.request.GET.get("guardian_id",None)
        family_income = self.request.GET.get("family_income",None)
        if application_id:
            filters["id"]=application_id
        if email:
            filters["email"]=email
        if search:
            filters["name__icontains"]=search
        if state:
            filters["state"] = state
        if country:
            filters["country"] = country
        if region:
            filters["region"] = region
        if gender:
            filters["gender"] = gender
        if child_type:
            filters["child_type"] = child_type
        if guardian :
            filters["guardian"] = guardian
        if family_income:
            filters['annual_income'] = family_income
        queryset = Application.objects.filter(**filters,is_active = True)
        page = self.paginate_queryset(queryset,request)
        serializer = ApplicationDetailsSerializer(page,many=True)
        for i in serializer.data:
            try :
                profile =i.get('profile',None)
                if profile :
                    logger.info("profile :"+str(profile))
                    i['profile'] = profile.replace("https://yuppeducational-images.s3.amazonaws.com","https://d28rlmk1ou6g18.cloudfront.net")
            except Exception as e:
                logger.exception(traceback.format_exc())
                logger.exception("Exception occured :"+str(e))
                return Response({"status ": False,"error ": str})
        return Response({"status":True,"response":{"data":serializer.data}})

        

class SponsoredApplications(APIView,MyPaginator):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        filters={}
        sponsor_id = self.request.GET.get("sponsor_id")
        # application_id = self.request.GET.get("application_id",None)
        email = self.request.GET.get("email",None)
        search = self.request.GET.get("search",None)
        state = self.request.GET.get("state",None)
        country = self.request.GET.get("country",None)
        region = self.request.GET.get("region",None)
        gender = self.request.GET.get("gender",None)
        child_type = self.request.GET.get("child_type",None)
        guardian = self.request.GET.get("guardian_id",None)
        if email:
            filters["email"]=email
        if search:
            filters["name__icontains"]=search
        if state:
            filters["state"] = state
        if country:
            filters["country"] = country
        if region:
            filters["region"] = region
        if gender:
            filters["gender"] = gender
        if child_type:
            filters["child_type"] = child_type
        if guardian :
            filters["guardian"] = guardian
        logger.info("Filters : "+str(filters))
        try:
            applicationIds = Sponsorship.objects.filter(sponsor_id = sponsor_id,is_active=True).values_list('application',flat=True)
            logger.info("Application Ids :"+str(applicationIds))
            queryset = Application.objects.filter(id__in=applicationIds,**filters,is_active=True)
            logger.info("query set : "+str(queryset))
            page = self.paginate_queryset(queryset,request)
            serializer = ApplicationDetailsSerializer(page,many=True)
            logger.info(serializer.data)
            if (len(serializer.data) >0):
                return Response({"status":True,"response":{"SponsoredApplications":{"sponsor_id":sponsor_id,"application":serializer.data}}})
            else :
                return Response({"status" :False,"error":{"message" : "You haven't sponsored any child yet"}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception("Exception occured :"+str(e))
            return Response({"status ": False,"error ": str})


class getBankDetails(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def get(self,request):
        logger.info(str(request.data))
        ApplicationId = request.GET.get("application_id")
        if ApplicationId :
            if BankDetails.objects.filter(application_id = ApplicationId,is_active = True).exists():
                bank_obj = BankDetails.objects.get(application_id = ApplicationId)
                serializer = ClientBankDetailsSerializer(bank_obj)
                logger.info(serializer.data)
                return Response({"status":True,"response":serializer.data})
            else :
                logger.info("No bank details found : "+ApplicationId)
                return Response({"status":False,"error":{"message":"No Bank Details Found"}})
        else :
            return Response({"status":False,"error":{"message":"missing parameter application_id"}})

class UpdateBankDetails(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = self.request.data
        id = data.get("id",None)
        if id:
            try:
                instance = BankDetails.objects.get(id = data['id'])
                data['created_by'] = instance.created_by
                data['last_updated_by'] = request.user.name
                data['application'] = data.pop("application_id")
                serializer = BankDetailsSerializer(instance,data=data)
                if serializer.is_valid():
                    updatedBankDetails=serializer.save()
                    logger.info("updatedBankDetails :")
                    logger.info(updatedBankDetails)
                    response = ClientBankDetailsSerializer(updatedBankDetails)
                    logger.info(response.data)
                    return Response({"status":True,"response":{"data":response.data}})
                else:
                    return Response({"status":False,"error":{"message":serializer.errors}})
            except BankDetails.DoesNotExist:
                return Response({"status":False,"error":{"message":"bank details doesn't exist with the given id "}})
        else :
            return Response({"status":False,"error":{"message":"id field is required"}})

            
class AddBankDetails(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = self.request.data
        logger.info("Bank Details Payload :"+str(data))
        try :
            application = data["application_id"]
            if BankDetails.objects.filter(application_id = application).exists():
                return Response({"status":False,"error":{"message":"Bank Details already exists for this application"}})
            else :
                data['created_by'] = request.user.name
                data['last_updated_by'] = request.user.name
                logger.info("Application Id :"+str(data["application_id"]))
                # data['application_id'] = int(data.pop("application"))
                serializer = BankDetailsSerializer(data = data)
                if serializer.is_valid():
                    serializer.create(data)
                    logger.info(serializer.data)
                    response = ClientBankDetailsSerializer(data)
                    return Response({"status":True,"response":{"data":response.data}})
                else :
                    logger.error(serializer.errors)
                    return Response({"status":False,"error":{"message":serializer.errors}})
        except Exception as e:
            logger.exception(str(e))
            # raise APIException
            return Response({"status":False,"error":{"message":str(e)}})




class getApplicationDocuments(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    parser_class = (FileUploadParser,)

    def get(self,request):
        ApplicationId = request.GET.get("application_id")
        logger.info("Application Id : "+ApplicationId)
        if ApplicationId :
            try :
                result =[]
                applicationDocuments = ApplicationDocument.objects.filter(application_id = ApplicationId,is_active=True)
                for i in applicationDocuments:
                    data ={}
                    document_type = {}
                    document_type['id'] = i.document_type.id
                    document_type['name'] = i.document_type.name
                    document_type['type'] = i.document_type.type
                    document_type['description'] = i.document_type.description
                    data['application_id'] = i.id
                    data['document_type'] = document_type
                    data['file_type'] = i.file_type
                    data['seq_no'] = i.seq_no
                    data['url']=i.url.url.replace("https://yuppeducational-images.s3.amazonaws.com","https://d28rlmk1ou6g18.cloudfront.net")
                    result.append(data)
                logger.info(result)
                serializer = ClientApplicationDocumentsSerializer(applicationDocuments,many = True)
                import json
                return Response({"status":True,"response":result})
            except ApplicationDocument.DoesNotExist:
                logger.error("Application Id doesn't exist : "+str(ApplicationId))
                return Response({"status":False,"error":{"message":str(ApplicationDocument.DoesNotExist)}})
        else :
            return Response({"status":False,"error":{"message":"missing parameter application_id"}})



def validate_ids(data, field="id", unique=True):

        if isinstance(data, list):
            id_list = [int(x[field]) for x in data]

            if unique and len(id_list) != len(set(id_list)):
                raise ValidationError("Multiple updates to a single {} found".format(field))

            return id_list

        return [data]

class BulkUpdateApplicationDocument(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    parser_class = (FileUploadParser,)
    
    def post(self,request):
        data = self.request.data
        # ids = validate_ids(request.data)
        id = data.get("id",None)
        if id:
            try:
                instance = ApplicationDocument.objects.get(id = data['id'])
                data['created_by'] = instance.created_by
                data['last_updated_by'] = request.user.name
                # data['application'] = data.pop("application_id")
                serializer = ApplicationDocumentsSerializer(instance,data=data)
                if serializer.is_valid():
                    try:
                        updatedDocuments=serializer.save()
                        logger.info("updatedDocuments :")
                        logger.info(updatedDocuments)
                        response = ClientApplicationDocumentsSerializer(updatedDocuments)
                        logger.info(response.data)
                        return Response({"status":True,"data":response.data})
                    except Exception as e:
                        logger.exception(str(e))
                        return Response({"status":False,"error":{"message":str(e)}})

                else:
                    logger.error(str(e))
                    return Response({"status":False,"error":{"message":serializer.errors}})
            except ApplicationDocument.DoesNotExist:
                logger.error(str(e))
                return Response({"status":False,"error":ApplicationDocument.DoesNotExist})
        else :
            return Response({"status":False,"error":{"message":"id field is missing","details":data}})

# def getCommonPath(fileType, fileName):
#     if fileType == "application_document" :
#         return "documents/"+"files"+fileName
#     else :
#         return fileType+"/images/"+fileName


# def upload_to_s3(fileType,filepath,fileName):
#     access_key =settings.AWS_ACCESS_KEY_ID
#     access_secret_key = settings.AWS_SECRET_ACCESS_KEY
#     bucket_name = settings.AWS_STORAGE_BUCKET_NAME 
#     client = boto3.client('s3',aws_access_key_id = access_key,aws_secret_access_key= access_secret_key)
#     path = getCommonPath(fileType, fileName)
#     r = client.uploadFile(bucket_name, path, new File(compressedImageLocation))

def upload_to_s3(file_path,file_name,application_id):
    access_key =settings.AWS_ACCESS_KEY_ID
    access_secret_key = settings.AWS_SECRET_ACCESS_KEY
    bucket_name = settings.AWS_STORAGE_BUCKET_NAME 
    client = boto3.client('s3',aws_access_key_id = access_key,aws_secret_access_key= access_secret_key)
    try :
        client.upload_file(file_path,bucket_name,f'doc/application_'+application_id+'/'+{file_name})
        url = 'doc/application_'+application_id+'/'+file_name
    except Exception as e:
        logger.error("Exception has occured in upload file ",e)
        return None
    return url


class UpdateApplicationDocument(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    parser_class = (FileUploadParser,)
    
    def post(self,request):
        data = self.request.data
        id = data.get("id",None)
        if id:
            try:
                instance = ApplicationDocument.objects.get(id = data['id'])
                data['created_by'] = instance.created_by
                data['last_updated_by'] = request.user.name
                data['is_active'] = True
                # data['application'] = data.pop("application_id")
                serializer = ApplicationDocumentsSerializer(instance,data=data)
                if serializer.is_valid():
                    try:
                        result =[]
                        updatedDocuments=serializer.save()
                        logger.info("updated Documents"+str(updatedDocuments))
                        data ={}
                        document_type = {}
                        document_type['id'] = updatedDocuments.document_type.id
                        document_type['name'] = updatedDocuments.document_type.name
                        document_type['type'] = updatedDocuments.document_type.type
                        document_type['description'] = updatedDocuments.document_type.description
                        data['application_id'] = updatedDocuments.id
                        data['document_type'] = document_type
                        data['file_type'] = updatedDocuments.file_type
                        data['seq_no'] = updatedDocuments.seq_no
                        data['url']= updatedDocuments.url.url.replace("https://yuppeducational-images.s3.amazonaws.com","https://d28rlmk1ou6g18.cloudfront.net")
                        result.append(data)
                        logger.info(result)
                        # print("updatedDocuments :")
                        # print(updatedDocuments)
                        # response = ClientApplicationDocumentsSerializer(updatedDocuments)
                        # logger.info(response.data)
                        return Response({"status":True,"response":{"data":result}})
                    except Exception as e:
                        logger.exception(str(e))
                        return Response({"status":False,"error":{"message":str(e)}})

                else:
                    logger.error(serializer.errors)
                    return Response({"status":False,"error":{"message":serializer.errors}})
            except ApplicationDocument.DoesNotExist as e:
                logger.error(str(e))
                return Response({"status":False,"error":"Application Document Query Doesn't exist"})
        else :
            return Response({"status":False,"error":{"message":"id field is missing","details":data}})



class AddApplicationDocument(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    parser_class = (FileUploadParser,)

    def post(self,request):
        data = self.request.data
        logger.info(data)
        # application = data["application_id"]
        data['created_by'] = request.user.name
        data['last_updated_by'] = request.user.name
        data['is_active'] = True
        # data['application'] = data.pop('application_id')
        # data['document_type'] = data.pop('document_type_id')
        # data['application_id'] = data.pop("application_id")
        serializer = ApplicationDocumentsSerializer(data = request.data)
        if serializer.is_valid():
            try:
                result =[]
                res =serializer.save()
                data ={}
                document_type = {}
                document_type['id'] = res.document_type.id
                document_type['name'] = res.document_type.name
                document_type['type'] = res.document_type.type
                document_type['description'] = res.document_type.description
                data['document_id'] = res.id
                data['document_type'] = document_type
                data['file_type'] = res.file_type
                data['seq_no'] = res.seq_no
                data['url']= res.url.url.replace("https://yuppeducational-images.s3.amazonaws.com","https://d28rlmk1ou6g18.cloudfront.net")
                result.append(data)
                # print(result)
                # response = ClientApplicationDocumentsSerializer(res)
                # print(response)
                return Response({"status":True,"response":{"data":result}})
            except Exception as e:
                logger.exception(e)
                # raise APIException
                return Response({"status ":False,"error":str(e)})
        else :
            return Response({"status":False,"error":serializer.errors})


class AddApplicationDocumentVersion2(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    parser_class = (FileUploadParser,)

    def post(self,request):
        data = self.request.data
        logger.info(data)
        # application = data["application_id"]
        data['created_by'] = request.user.name
        data['last_updated_by'] = request.user.name
        # data['application'] = data.pop('application_id')
        # data['document_type'] = data.pop('document_type_id')
        # data['application_id'] = data.pop("application_id")
        serializer = ApplicationDocumentsSerializer(data = request.data)
        if serializer.is_valid():
            try:
                res =serializer.save()
                response = ClientApplicationDocumentsSerializer(res)
                logger.info(response)
                return Response({"status":True,"response":{"data":response.data}})
            except Exception as e:
                logger.exception(e)
                # raise APIException
                return Response({"status ":False,"error":str(e)})
        else :
            return Response({"status":False,"error":serializer.errors})




class BulkInsertApplicationDocument(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    parser_class = (FileUploadParser,)

    def post(self,request):
        data1 = self.request.data
        logger.info(data1)
        try:
            with transaction.atomic():
                for data in data1:
                    data['created_by'] = request.user.name
                    data['last_updated_by'] = request.user.name
                    serializer = ApplicationDocumentsSerializer(data = request.data,many=True)
                    if serializer.is_valid():
                        try:
                            res =serializer.save()
                            response = ClientApplicationDocumentsSerializer(res)
                            return Response({"status":True,"response":{"data":response.data}})
                        except Exception as e:
                            logger.exception(e)
                            # raise APIException
                            return Response({"status ":False,"error":str(e)})
                    else :
                        logger.error(serializer.errors)
                        return Response({"status":False,"error":serializer.errors})
        except Exception as e:
            logger.error(str(e))
            return Response({"status":False,"error":{"message":"Error while inserting","detail":str(e)}})
                

class RemoveApplicationDocuments(APIView):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        ids = request.data['ids']
        logger.info(ids)
        try:
            with transaction.atomic() :
                for id in ids:
                    applicationObj =ApplicationDocument.objects.get(pk = id)
                    applicationObj.delete()
            return Response({"status":True,"response":{"message":"Documents deleted successfully"}})
        except ApplicationDocument.DoesNotExist:
            logger.error(str(ApplicationDocument.DoesNotExist))
            return Response({"status":False,"error":{"message":"Application does not exist please check the Id's"}})
        except Exception as e:
            logger.error(str(e))
            return Response({"status":False,"error":{"message":str(e)}})


class UpdateApplicationProfile(APIView):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = request.data
        logger.info(data)
        id = request.data["id"]
        if id:
            if Application.objects.filter(id = data['id']).exists():
                # email_exists = Application.objects.filter(email=data['email']).exclude(id = data["id"]).exists()
                # mobile_exists = Application.objects.filter(mobile=data['mobile']).exclude(id = data["id"]).exists()
                # if email_exists and mobile_exists:
                #     return Response({"status":False,"error":{"message":"Email and Mobile already Exists"}})
                # elif email_exists:
                #     return Response({"status":False,"error":{"message":"Application already exists with the given email"}})
                # elif mobile_exists :
                #     return Response({"status":False,"error":{"message":"Application already exists with the given mobile"}})
                # else:
                    data = request.data
                    # data['birthday'] = time.strptime(data.pop('birthday'), "%d-%m-%Y").strptime("%y/%m-%d")
                    data['last_updated_by']=request.user.name
                    application_data = Application.objects.get(id = data['id'])
                    application_data.email = data.get('email',application_data.email)
                    application_data.name = data.get('name',application_data.name)
                    application_data.birthday = data.get('birthday',application_data.birthday)
                    application_data.child_type_id = data.get('child_type_id',application_data.child_type)
                    application_data.gender_id = data.get('gender_id',application_data.gender)
                    application_data.last_updated_by = data.get('last_updated_by',application_data.last_updated_by)

                    try:
                        application_data.save()
                        serializer = ApplicationDetailsSerializer(application_data)
                        updateChildtoZoho(serializer.data)
                        return Response({"status":True,"data":serializer.data})
                    except IntegrityError as e:
                        logger.exception(str(e))
                        raise ValidationError({"400": f'{str(e)}'})
                    except Exception as e:
                        logger.exception(str(e))
                        return Response({"status":False,"error":{"message":str(e)}})
            else :
                logger.exception("Application Doesn't exist")
                return Response({"status":404,"error":{"message":"Application Doesn't exist"}})
        else:
            logger.exception("Id not found")
            return Response({"status":False,"error":{"message":"Not found value id"}})
            

class AddApplicationProfile(APIView):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = request.data
        logger.info(data)
        email_exists = Application.objects.filter(email=data.get('email',None)).exists()
        # mobile_exists = Application.objects.filter(mobile=data.get('mobile',None)).exists()
        logger.info("email exists : "+str(email_exists))
        # logger.info("mobile exists : "+str(mobile_exists))
        # if email_exists and mobile_exists:
        #     return Response({"status":False,"error":{"message":"Email and Mobile already Exists"}})
        if email_exists:
            return Response({"status":False,"error":{"message":"Email already linked to other application"}})
        # elif mobile_exists :
        #     return Response({"status":False,"error":{"message":"Mobile already linked to other application"}})
        else:
            data['created_by'] = request.user.name
            data['last_updated_by'] = request.user.name
            try:
                data = Application.objects.create(**data)
                logger.info(data)
                serializer = ApplicationDetailsSerializer(data)
                addChildToZoho(serializer.data)
                return Response({"status":True,"response":{"data":serializer.data}})
            except IntegrityError as e:
                logger.exception(str(e))
                raise ValidationError({"400": f'{str(e)}'})
            except Exception as e :
                logger.exception(str(e))
                # raise APIException
                return Response({"status":False,"error":{"message":str(e)}})


class AddApplication(APIView):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = ApplicationSerializer

    def post(self,request):
        data = self.request.data
        data['created_by'] = request.user.name
        data['last_updated_by'] = request.user.name
        data["child_type"] = EnumChildType.objects.filter(type=data.pop("child_type")).first().id
        data["gender"] = EnumGender.objects.filter(gender=data.pop("gender")).first().id
        serializer = ApplicationSerializer(data=data)
        if serializer.is_valid():
            serializer.create(data)
            logger.info(serializer.data)
            return Response({"status":True,"response":{"data":serializer.data}})
        else :
            logger.error(serializer.errors)
            return Response({"status":False,"error":{"message":serializer.errors}})


class UpdateEducationalDetails(APIView):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self,request):
        data = request.data
        try:
            application_data = Application.objects.get(pk = data['application_id'])
            application_data.grade = data.get('grade',application_data.grade)
            application_data.school =  data.get('school',application_data.school)
            application_data.school_address =  data.get('school_address',application_data.school_address)
            application_data.hobbies =  data.get('hobbies',application_data.hobbies)
            application_data.aspirations =  data.get('aspirations',application_data.aspirations)
            application_data.achievements =  data.get('achievements',application_data.achievements)
            application_data.last_updated_by =  request.user.name
            try:
                application_data.save()
                serializer = ApplicationDetailsSerializer(application_data)
                logger.info(serializer.data)
                updateChildtoZoho(serializer.data)
                return Response({"status":True,"response":{"data":serializer.data}})
            except IntegrityError as e:
                logger.exception(str(e))
                raise ValidationError({"400": f'{str(e)}'})
            except Exception as e:
                logger.exception(str(e))
                # raise APIException
                return Response({"status":False,"error":{"message":str(e)}})
        except Application.DoesNotExist:
            logger.error("Application DoesNotExist")
            return Response({"status":False,"error":{"message":str(Application.DoesNotExist)}})


class SponsorKid(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = self.request.data
        data['created_by'] = request.user.name
        data['last_updated_by'] = request.user.name
        data['sponsor'] = Sponsor.objects.filter(pk = data.pop("sponsor_id")).first().id
        application_id = data['application_id']
        data['application'] = data.pop("application_id")
        if Sponsorship.objects.filter(sponsor_id =data['sponsor'],application_id = data['application']).exists():
            return Response({"status":False,"error":{"message":"You have already sponsored for this kid"}})
        else :
            serializer = SponsorshipSerializer(data=data)
            if serializer.is_valid():
                try:
                    serializer.create(data)
                    # logger.info(status)
                    # ApplicationObj = Application.objects.get(pk= application_id)
                    # ApplicationObj.status_id = status
                    # ApplicationObj.last_updated_by = request.user.name
                    # ApplicationObj.save()
                    logger.info(serializer.data)
                    SponsorshipObj = Sponsorship.objects.latest('id')
                    res = ClientSponsorshipSerializer(SponsorshipObj)
                    logger.info(res.data)
                    return Response({"status":True,"response":{"data":res.data}})
                except Exception as e:
                    logger.exception(str(e))
                    return Response({"status":False,"error":{"message":str(e)}})
            else :
                logger.error(serializer.errors)
                return Response({"status":False,"error":{"message":serializer.errors}})

class UpdateSponsorship(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self,request):
        data = self.request.data
        logger.info(data)
        id = data.get("id",None)
        if id:
            try:
                instance = Sponsorship.objects.get(id = data['id'])
                data['created_by'] = instance.created_by
                data['last_updated_by'] = request.user.name
                data['application'] = data.pop("application_id")
                data['sponsor'] = data.pop("sponsor_id")
                serializer = SponsorshipSerializer(instance,data=data)
                if serializer.is_valid():
                    res=serializer.save()
                    logger.info("updated Data :")
                    logger.info(res)
                    logger.info(res)
                    response = ClientSponsorshipSerializer(res)
                    return Response({"status":True,"response":{"data":response.data}})
                else:
                    logger.error(serializer.errors)
                    return Response({"status":False,"error":{"message":serializer.errors}})
            except IntegrityError as e:
                logger.exception(str(e))
                raise ValidationError({"400": f'{str(e)}'})
            except Sponsorship.DoesNotExist:
                logger.exception(Sponsorship.DoesNotExist)
                return Response({"status":False,"error":{"message":str(Sponsorship.DoesNotExist)}})
        else :
            return Response({"status":False,"error":{"message":"id field is required"}})


class UpdateGuardianDetails(APIView):
    permission_classes =[IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self,request):
        data = self.request.data
        logger.info(data)
        try:
            application_data = Application.objects.get(id = data['application_id'])
            application_data.profession =  data.get('profession',application_data.profession)
            application_data.annual_income =  data.get('annual_income',application_data.annual_income)
            application_data.family_members =  data.get('family_members',application_data.family_members)
            application_data.extra_allowance =  data.get('extra_allowance',application_data.extra_allowance)
            application_data.last_updated_by =  request.user.name
            try:
                application_data.save()
                serializer = ApplicationDetailsSerializer(application_data)
                updateChildtoZoho(serializer.data)
                return Response({"status":True,"response":{"data":serializer.data}})
            except IntegrityError as e:
                logger.exception(str(e))
                raise ValidationError({"400": f'{str(e)}'})
            except Exception as e:
                logger.exception(str(e))
                # raise APIException
                return Response({"status":False,"error":{"message":str(e)}})
        except Application.DoesNotExist:
            logger.exception(Application.DoesNotExist)
            return Response({"status":False,"error":{"message":"Application doesn't exist with the given id"}})

import chargebee
from chargebee import InvalidRequestError


chargebee.configure(settings.CHARGEBEE_APIKEY, settings.CHARGEBEE_SITENAME)


class createCustomer(APIView):
    def post(self,request):
        try:
            with transaction.atomic():
                data = {}
                data['role'] = request.data.pop('role')
                request.data['id'] = data['role']+"_"+str(random.randint(100000,999999))
                customer = chargebee.Customer.create(request.data)
                logger.info(customer.__dict__)
                # print(User.objects.filter(pk=request.data.pop('user_id')).first().id)
                data['user_id'] = User.objects.filter(pk=request.data.pop('user_id')).first().id
                data['customer_id'] = customer.customer.id
                serializer = ChargebeeUserSerializer(data = data)
                if serializer.is_valid():
                    serializer.create(data)
                    return Response({"status":True,"response":customer.__dict__['_response']})
                return Response({"status":False,"error":{"message":serializer.errors}})
        except InvalidRequestError as e:
            logger.exception(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.exception(str(e))
            return Response({"status":False,"error":{"message":str(e)}})


class updateSubscriptionDetails(APIView):
    permission_classes = (AllowAny,)
    def post(self,request):
        data = self.request.data
        logger.info(data)
        try:
            logger.info(data['content']['subscription']['id'])
            # sponsorshipPayment = SponsorshipPayment.objects.get(id = data['content']['subscription']['id'])
            # print(sponsorshipPayment)
            dataObj = json.dumps(data)
            subscription ={}
            sponsorship = Sponsorship.objects.get(pk = data['content']['subscription']['id'])
            reference_id = data['content']['customer']['payment_method']['reference_id']
            payment_date = datetime.fromtimestamp(data['content']['subscription']['created_at'],tz=get_current_timezone())
            currency = data['content']['subscription']['currency_code']
            amount =  data['content']['subscription']['subscription_items'][0]['amount']
            next_billing_at = datetime.fromtimestamp(data['content']['subscription']['next_billing_at'],tz=get_current_timezone())  
            billing_period_unit = data['content']['subscription']['billing_period_unit']
            subscription_data = json.loads(json.dumps(data))
            payment_status = data['content']['subscription']['status']
            # print(amount)
            # if amount:
            #     sponsorshipPayment.amount = amount
            # if currency_code:
            #     sponsorshipPayment.currency_code = currency_code
            # if billing_period :
            #     sponsorshipPayment.billing_period = billing_period
            # print(sponsorshipPayment)
            Sponsorship.objects.filter(id = data['content']['subscription']['id']).update(status = payment_status)
            applicationId = Sponsorship.objects.filter(id = data['content']['subscription']['id']).first().application_id
            logger.info(applicationId)
            status =EnumApplicationStatus.objects.get(status = 'scholorship-received').id
            logger.info(status)
            Application.objects.filter(id = applicationId).update(status= status)
            res = SponsorshipPayment.objects.create(sponsorship = sponsorship,reference_id = reference_id,payment_date = payment_date,currency = currency,amount = amount,next_billing_at = next_billing_at,billing_period_unit = billing_period_unit,subscription_data = subscription_data)
            return Response({"status ":True,"response":{"message":"Successfully updated subscription details"}})
            # serializer = SponsorshipPaymentSerializer(data = subscription.data)
            # if serializer.is_valid():
            #     try:
            #         res =serializer.save()
            #         response = ClientSponsorshipPaymentSerializer(res)
            #         print(response)
            #         return Response({"status":True,"response":{"data":response.data}})
            #     except Exception as e:
            #         logger.exception(e)
            #         return Response({"status ":False,"error":str(e)})
            # else :
                # return Response({"status":False,"error":{"message":serializer.errors}})
            # try:
            #     sponsorshipPayment.save()
            #     serializer = UpdateSponsorshipSerializer(sponsorshipPayment)
            #     return Response({"status":True,"response":serializer.data})
            # except IntegrityError as e:
            #     logger.exception(str(e))
            #     raise ValidationError({"400": f'{str(e)}'})
            # except Exception as e:
            #     logger.exception(str(e))
            #     # raise APIException
            #     return Response({"status":False,"error":{"message":str(e)}})
        except Sponsorship.DoesNotExist:
            logger.exception(Sponsorship.DoesNotExist)
            return Response({"status":False,"error":{"message":"Sponsor Application doesn't exist with the given id"}})
        except Exception as e:
            logger.exception(traceback.format_exc())
            logger.exception("Exception occured :"+str(e))


global ZOHO_ACCESS_TOKEN 
global ZOHO_USER_MODULE_ACCESS_TOKEN
ZOHO_ACCESS_TOKEN = "1000.615d83a2de4d8fde1211a264468dde1e.93b964add710ac76d2c79cf3ced766f9"
def refreshToken():
    url = "https://accounts.zoho.in/oauth/v2/token"
    formFields = {"client_id": settings.ZOHO_CLIENT_ID, "client_secret" : settings.ZOHO_CLIENT_SECRET, "refresh_token" : settings.ZOHO_REFRESH_TOKEN, "grant_type" : "refresh_token"}
    response = requests.post(url, data = formFields)
    logger.info("response"+str(response))
    if response.status_code == requests.codes.ok : 
        token = response.json()
        logger.info("token"+str(token))
        ZOHO_ACCESS_TOKEN = token.get('access_token')
        logger.info("Zoho-oauthtoken"+str(token.get('access_token')))
        # return ZOHO_ACCESS_TOKEN
    else :
      logger.error("Error from zoho token api")
    #   return ""

ACCESS_TOKEN_CACHE_KEY = 'access_token'
ACCESS_TOKEN_REFRESH_THRESHOLD_MINUTES = 5

def get_access_token():
    access_token = cache.get(ACCESS_TOKEN_CACHE_KEY)
    print(access_token)
    if access_token is None:
        # Token not found in cache, obtain new token from API
        url = "https://accounts.zoho.in/oauth/v2/token"
        formFields = {"client_id": settings.ZOHO_CLIENT_ID, "client_secret" : settings.ZOHO_CLIENT_SECRET, "refresh_token" : settings.ZOHO_REFRESH_TOKEN, "grant_type" : "refresh_token"}
        response = requests.post(url, data = formFields)
        logger.info("response"+str(response.json()))
        if response.status_code == requests.codes.ok :
            res = response.json()
            print(res)
            logger.info("token"+str(res))
            access_token = res.get('access_token')
            logger.info("Zoho-oauthtoken"+str(res.get('access_token'))) 

            # Store token in cache with expiration time
            expiration_time = datetime.now() + timedelta(seconds=res.get('expires_in'))
            cache.set(ACCESS_TOKEN_CACHE_KEY, access_token, timeout=(expiration_time - datetime.now()).seconds)
        else :
            logger.error("Error from zoho token api")
            logger.error(str(response.json()))
    else:
        # Token found in cache, check if it's close to expiring
        expiration_time = cache.get(ACCESS_TOKEN_CACHE_KEY + '_expiration')
        if expiration_time is not None and (expiration_time - datetime.now()).seconds < ACCESS_TOKEN_REFRESH_THRESHOLD_MINUTES * 60:
            # Token is close to expiring, obtain new token from API
            url = "https://accounts.zoho.in/oauth/v2/token"
            formFields = {"client_id": settings.ZOHO_CLIENT_ID, "client_secret" : settings.ZOHO_CLIENT_SECRET, "refresh_token" : settings.ZOHO_REFRESH_TOKEN, "grant_type" : "refresh_token"}
            response = requests.post(url, data = formFields)
            logger.info("response"+str(response))
            if response.status_code == requests.codes.ok :
                res = response.json()
                logger.info("token"+str(res))
                access_token = res.get('access_token')
                logger.info("Zoho-oauthtoken"+str(res.get('access_token'))) 

                # Update token in cache with new expiration time
                expiration_time = datetime.now() + timedelta(seconds=res.get('expires_in'))
                cache.set(ACCESS_TOKEN_CACHE_KEY, access_token, timeout=(expiration_time - datetime.now()).seconds)
            else :
                logger.error("Error from zoho token api")
                logger.error(str(response.json()))
    print(access_token)
    return access_token


def refreshUserModuleToken():
    url = "https://accounts.zoho.in/oauth/v2/token"
    formFields = {"client_id" : settings.ZOHO_CLIENT_ID, "client_secret" : settings.ZOHO_CLIENT_SECRET, "refresh_token" : settings.ZOHO_USER_MODULE_REFRESH_TOKEN, "grant_type" : "refresh_token"}
    response = requests.post(url, data =formFields)
    if response.status_code == requests.codes.ok :
        token = response.json()
        logger.info("token"+str(token))
        ZOHO_USER_MODULE_ACCESS_TOKEN = token.get('access_token')
        logger.info("Zoho-user_module_access_token"+str(token.get('access_token')))
        return ZOHO_USER_MODULE_ACCESS_TOKEN
    else :
      logger.error("Error from zoho token api")
      return ""
    