from .base import *
import os
from pathlib import Path

from decouple import config

SECRET_KEY = config('SECRET_KEY')

DEBUG = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:4200",
    "http://127.0.0.1:8000",
]

DATABASES = {

    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'postgres', 
        'USER': 'postgres', 
        'PASSWORD': 'Deigfh@504',
        'HOST': '43.205.14.149', 
        'PORT': '5432',
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    # {
    #     'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    # },
    # {
    #     'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    # },
]


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

STATICFILES_DIRS = [
os.path.join(BASE_DIR,'static')]   # This is your static folder

STATIC_ROOT = os.path.join(BASE_DIR,'assets') # This is your assets folder

MEDIA_URL = '/media/'

MEDIA_ROOT =  os.path.join(BASE_DIR,'media')

#HTTPS settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True

#HSTS settings
SECURE_HSTS_SECONDS = 31526000  # 1 year
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True


#Email Configuration

SERVER_EMAIL = config('DEFAULT_FROM_EMAIL')

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.office365.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')

ADMINS = (
    ("Balaji", "balajit@turito.com"),
)

MANAGERS = ADMINS

#AWS S3 configurations

AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME')
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
# STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_S3_SIGNATURE_VERSION = "s3v4"
AWS_QUERYSTRING_AUTH = False

STATIC_URL = f'https://{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/static/'

#Chargebee Configuration

CHARGEBEE_APIKEY = config('CHARGEBEE_APIKEY')
CHARGEBEE_SITENAME = config('CHARGEBEE_SITENAME')

# SOCIALACCOUNT_PROVIDERS = {
#     'google': {
#         'APP': {
#             'client_id': 'YOUR_CLIENT_ID',
#             'secret': 'YOUR_CLIENT_SECRET',
#             'key': ''
#         },
#         'SCOPE': [
#             'profile',
#             'email'
#         ],
#         'AUTH_PARAMS': {
#             'access_type': 'online'
#         }
#     }
# }