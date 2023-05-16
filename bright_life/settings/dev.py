from .base import *

import os
from pathlib import Path

from decouple import config

# SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = 'django-insecure-w^$@6#zzp^y20a*&%b=22fdf2e9&*@vb!tz_7^dh690f+r2w)_'

SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False


ALLOWED_HOSTS = [
    "*"
    ]

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:4200",
#     "http://127.0.0.1:8000",
#     "http://43.205.14.149:8000",
# ]
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = False


# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': config('DEV_DB'), 
        'USER': config('DEV_USER'), 
        'PASSWORD': config('DEV_PASSWORD'),
        'HOST': config('DEV_HOST'), 
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

STATIC_ROOT = os.path.join(BASE_DIR,'static')

# STATICFILES_DIRS = [os.path.join(BASE_DIR,'static')]

# STATICFILES_DIRS = [
# os.path.join(BASE_DIR,'static')]   # This is your static folder

# STATIC_ROOT = os.path.join(BASE_DIR,'assets') # This is your assets folder

MEDIA_URL = '/media/'

MEDIA_ROOT =  os.path.join(BASE_DIR,'media')

#HTTPS settings
# SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False

#HSTS settings
SECURE_HSTS_SECONDS = 31526000  # 1 year
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

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



AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME')
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
# STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_S3_SIGNATURE_VERSION = "s3v4"
AWS_QUERYSTRING_AUTH = False

# STATIC_URL = f'https://{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/static/'


#Chargebee Configuration

CHARGEBEE_APIKEY = config('CHARGEBEE_APIKEY')
CHARGEBEE_SITENAME = config('CHARGEBEE_SITENAME')

ZOHO_CLIENT_ID = config('ZOHO_CLIENT_ID')
ZOHO_CLIENT_SECRET =config('ZOHO_CLIENT_SECRET')
ZOHO_REFRESH_TOKEN =config('ZOHO_REFRESH_TOKEN')
ZOHO_USER_MODULE_REFRESH_TOKEN =config('ZOHO_USER_MODULE_REFRESH_TOKEN')
ZOHO_API_INITIAL_PATH =config('ZOHO_API_INITIAL_PATH')

# Stripe Configurations
STRIPE_PUBLISHABLE_KEY = config('STRIPE_PUBLISHABLE_KEY')
STRIPE_SECRET_KEY = config('STRIPE_SECRET_KEY')
STRIPE_PRODUCT_ID = config('STRIPE_PRODUCT_ID')
STRIPE_WEBHOOK_SECRET = config('STRIPE_WEBHOOK_SECRET')


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'all_file': {
            'class': 'logging.FileHandler',
            'filename': 'log.txt',
            'level': 'DEBUG'
        },
    },
    'root': {
            'handlers': ['all_file'],
    },
}


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