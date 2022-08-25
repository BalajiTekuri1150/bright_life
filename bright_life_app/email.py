from turtle import update
from django.core.mail import send_mail
import random
from .models import User,OtpMaster
from django.conf import settings
from datetime import datetime, timedelta

import os

from .logger import *
# def update_otp(data):
#         expiry_time = datetime.now() + timedelta(minutes = 2)
#         try:
#             OtpMaster.objects.create(target = data.get("email"),user= data.get("user_id"),otp=data.get("otp"),expiry_date=expiry_time)
#         except Exception as e:
#             print(e)

class EmailSender:

    def send_email(data):
        email = data['to_email']
        subject = data['subject']
        message = data['email_body']
        email_from = settings.EMAIL_HOST_USER
        logger.info("from email : "+str(email_from))
        logger.info("Send mail request : "+str(data))
        print("email_from : "+str(email_from))
        try:
            logger.info("Before Sending email ")
            return send_mail(subject,message,email_from,[email])
        except Exception as e :
            logger.exception("Error while sending email : "+str(e))
            print("Exception raised when sending email : "+str(e))
            return -1

    # def send_email(data):
    #     try:
    #         send_mail(subject,message,email_from,[email])
    #     except Exception as e:
    #         print(e)


    