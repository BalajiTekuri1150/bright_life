from.base import *

import os
from pathlib import Path

from decouple import config


SECRET_KEY = config('SECRET_KEY')

DEBUG = config('DEBUG')

CHARGEBEE_APIKEY = config('CHARGEBEE_APIKEY')
CHARGEBEE_SITENAME = config('CHARGEBEE_SITENAME')

#Zoho configuration 
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

ALLOWED_HOSTS = ["*"]

CORS_ORIGIN_ALLOW_ALL=True

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:4200",
#     "http://127.0.0.1:8000",
# ]

# TEMPLATES = [
#     {
#         'BACKEND': 'django.template.backends.django.DjangoTemplates',
#         'DIRS': [os.path.join(BASE_DIR,'templates')],
#         'APP_DIRS': True,
#         'OPTIONS': {
#             'context_processors': [
#                 'django.template.context_processors.debug',
#                 'django.template.context_processors.request',
#                 'django.contrib.auth.context_processors.auth',
#                 'django.contrib.messages.context_processors.messages',
#             ],
#         },
#     },
# ]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'demo', 
        # 'USER': 'rivuletuser', 
        # 'PASSWORD': 'rivulet',
        # 'HOST': '127.0.0.1', 
        # 'PORT': '5432',
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
if not DEBUG:
    STATIC_ROOT = os.path.join(BASE_DIR, 'static')
else :
    STATICFILES_DIRS = [os.path.join(BASE_DIR,'static')]   # This is your static folder

# # STATIC_ROOT = os.path.join(BASE_DIR,'assets') # This is your assets folder
MEDIA_URL = '/media/'



MEDIA_ROOT =  os.path.join(BASE_DIR,'media')




#HTTPS settings
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False

#HSTS settings
SECURE_HSTS_SECONDS = 31526000  # 1 year
SECURE_HSTS_PRELOAD = False
SECURE_HSTS_INCLUDE_SUBDOMAINS = False

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
AWS_S3_REGION_NAME ="ap-south-1"
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
# STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_S3_SIGNATURE_VERSION = "s3v4"
AWS_QUERYSTRING_AUTH = False
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID')


CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        'LOCATION': '127.0.0.1:11211',
        'OPTIONS': {
            # 'TIMEOUT': 3600,  # cache expiration time in seconds
        },
    },
}

ASYNC_SUPPORT=True


SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': config('GOOGLE_CLIENT_ID'),
            'secret': config('GOOGLE_CLIENT_SECRET'),
            'key': ''
        },
        'SCOPE': [
            'profile',
            'email'
        ],
        'AUTH_PARAMS': {
            'access_type': 'online'
        }
    }
}
