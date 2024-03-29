import json
import random
from urllib import response
import chargebee
from django.conf import settings

from chargebee import InvalidRequestError
from django.http import HttpResponse

from rest_framework.views import APIView
from rest_framework.response import Response
from django.core import serializers
from django.http import JsonResponse
from django.db import transaction
# from .serializers import ChargebeeUserSerializer

from .logger import *

chargebee.configure(settings.CHARGEBEE_APIKEY, settings.CHARGEBEE_SITENAME)

def create_customer(data):
    if 'id' in data:
        del data['id']
        # Let chargebee handle creation of customer id

    try:
        result = chargebee.Customer.create(data)
        return result.customer
    except InvalidRequestError as e:
        return None

# class createCustomer(APIView):
#     def post(self,request):
#         try:
#             with transaction.atomic():
#                 data = {}
#                 data['role'] = request.data.pop('role')
#                 request.data['id'] = data['role']+"_"+str(random.randint(100000,999999))
#                 customer = chargebee.Customer.create(request.data)
#                 print(customer.__dict__)
#                 data['user_id'] = request.data.pop('user_id')
#                 data['customer_id'] = customer.customer.id
#                 serializer = ChargebeeUserSerializer(data = data)
#                 if serializer.is_valid():
#                     serializer.create(data)
#                     return Response({"status":True,"response":customer.__dict__['_response']})
#                 return Response({"status":False,"error":{"message":"error while creating Chargebee User"}})
#         except InvalidRequestError as e:
#             print(str(e))
#             return Response({"status":False,"error":{"message":str(e)}})
#         except Exception as e:
#             print(str(e))
#             return Response({"status":False,"error":{"message":str(e)}})


class createItemFamily(APIView):
    def post(self,request):
        logger.info(request.data)
        try:
            entries = chargebee.Item.list({
            })
            logger.info(entries)
            for entry in entries:
                item = entry.item
                logger.info(item)
            result = chargebee.ItemFamily.create({
                "id" : request.data['id'],
                "description" : request.data['description'],
                "name" : request.data['name']
                })
            logger.info(result)
            item_family = result.item_family
            return Response({'status':True,'response':{'data':item_family.__dict__}})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})


class createItem(APIView):
    def post(self,request):
        logger.info(request.data)
        try:
            result = chargebee.Item.create({
            "id" : request.data['id'],
            "name" : request.data['name'],
            "type" : request.data['type'],
            "description" : request.data['description'],
            "item_family_id" : request.data['item_family_id']
            })
            logger.info(result)
            item = result.item
            return Response({'status':True,'response':{'data':item.__dict__}})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})

class getItemsList(APIView):
    def get(self,request):
        try:
            entries = chargebee.Item.list({
                "item_family_id[is]" : request.GET.get('item_family_id','brightlife_sponsorship')
            })
            for entry in entries:
                item = entry.item
            if len(entries) >0:
                return Response({"status":True,"response":entries.__dict__['response']})
            else :
                return Response({"status":False,"response":"No Items Found"})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})



class createItemPrice(APIView):
    def post(self,request):
        logger.info(request.data)
        try:
            result = chargebee.ItemPrice.create({
            "id" : request.data['id'],
            "item_id" : request.data['item_id'],
            "name" : request.data['name'],
            "price" : request.data['price'],
            "period_unit" : request.data['period_unit'],
            "period" : request.data['period'],
            "currency_code" : request.data['currency_code']
            })
            logger.info(result)
            item_price = result.item_price
            return Response({'status':True,'response':{'data':item_price.__dict__}})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})


class updateItemPrice(APIView):
    def post(self,request):
        try:
            item_price_id = request.data['item_price_id']
            result = chargebee.ItemPrice.update(item_price_id,{
            "name" : request.data['name'],
            "price" : request.data['price'],
            "period" : request.data['period'],
            "period_unit" : request.data['period_unit']
            })
            item_price = result.item_price
            return Response({"status":True,"response":result.item_price})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})




class listCustomers(APIView):
    def get(self,request):
        try:
            response =[]
            entries = chargebee.Customer.list({
                "id[is]" : request.GET.get('id',None),
                "id[isnot]":None,
                "first_name[is]" : request.GET.get('first_name',None),
                "first_name[isnot]" : None,
                "last_name[is]" : request.GET.get('last_name',None),
                "last_name[isnot]" : None,
                "email[is]" : request.GET.get('email',None),
                "email[is]" : None
            })
            logger.info(entries)
            if len(entries) >0:
                return Response({"status":True,"response":entries.__dict__})
            else :
                return Response({"status":False,"error":"No customers found"})
        except InvalidRequestError as e:
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            return Response({"status":False,"error":{"message":str(e)}})


class getCheckoutPage(APIView):
    def post(self,request):
        logger.info(request.data)
        try:
            result = chargebee.HostedPage.checkout_new_for_items({
            # "shipping_address" : request.data['shipping_address'],
            "currency_code": request.data['currency_code'],
            "customer" : request.data['customer'],
            "subscription_items" : request.data['subscription_items'],
            "subscription" : request.data['subscription'],
            "redirect_url": request.data.get("redirect_url","https://brightlife.org/payment/successful"),
            "cancel_url": request.build_absolute_uri()
            })
            logger.info(result.hosted_page)
            hosted_page = result.hosted_page
            return Response({'status':True,"response":{"data":hosted_page.__dict__}})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        
    
class getOneTimeCheckoutPage(APIView):
    def post(self,request):
        logger.info(request.data)
        try:
            result = chargebee.HostedPage.checkout_one_time_for_items({
            # "shipping_address" : request.data['shipping_address'],
            "currency_code": request.data.get('currency_code'),
            "customer" : request.data.get('customer'),
            "item_prices" : request.data.get('item_prices'),
            "redirect_url": request.data.get("redirect_url","https://brightlife.org/payment/successful"),
            "cancel_url": request.build_absolute_uri()
            })
            logger.info(result.hosted_page)
            hosted_page = result.hosted_page
            return Response({'status':True,"response":{"data":hosted_page.__dict__}})
        except InvalidRequestError as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        except Exception as e:
            logger.info(str(e))
            return Response({"status":False,"error":{"message":str(e)}})


class getItemPricesList(APIView):

    def get(self,request):
        currency_code = request.GET.get("currency_code",None)
        item_id = request.GET.get("item_id",None)
        period = request.GET.get("period",None)
        period_unit = request.GET.get("period_unit",None)
        status = request.GET.get("status",None)
        next_offset = request.GET.get("next_offset",None)
        limit = request.GET.get("limit",50)
        logger.info(currency_code)
        filters ={}
        if currency_code:
            filters["currency_code[in]"] =currency_code
        if item_id:
            filters["item_id[is]"] = item_id
        if period:
            filters["period[is]"] = period
        if period_unit:
            filters["period_unit[in]"] = period_unit
        if status:
            filters["status[is]"] = status
        if next_offset:
            filters["next_offset"] = next_offset
        if limit:
            filters["limit"] = limit
        try:
            entries = chargebee.ItemPrice.list(
                filters
            )
            logger.info(entries)
            if len(entries) > 0:
                return Response({"status":True,"response":entries.__dict__})
            else :
                return Response({"status":False,"error":{"message":"No Item Prices found"}})
        except Exception as e:
            logger.error(str(e))
            return Response({"status":False,"error":{"message":str(e)}})
        







