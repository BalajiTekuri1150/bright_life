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
    '127.0.0.1',
    'localhost',
    ]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:4200",
    "http://127.0.0.1:8000",
]

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

STATICFILES_DIRS = [
os.path.join(BASE_DIR,'static')]   # This is your static folder

STATIC_ROOT = os.path.join(BASE_DIR,'assets') # This is your assets folder

MEDIA_URL = '/media/'

MEDIA_ROOT =  os.path.join(BASE_DIR,'media')

#HTTPS settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = False

#HSTS settings
SECURE_HSTS_SECONDS = 31526000  # 1 year
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.office365.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')



AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME')
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_S3_SIGNATURE_VERSION = "s3v4"
# AWS_QUERYSTRING_AUTH = False

# STATIC_URL = f'https://{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/static/'


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'papermerge': {
            'class': 'logging.FileHandler',
            'filename': 'papermerge.log',
            'level': 'DEBUG'
        },
    },
    'loggers': {
        'papermerge': {
            'handlers': ['papermerge'],
            'level': 'DEBUG'
        },
    },
}