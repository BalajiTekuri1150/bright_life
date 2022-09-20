from django.urls import URLPattern, path

from . import views

from .chargebee_utils import *
from django.conf.urls.static import static
from django.conf import  settings

from rest_framework.authtoken import views

urlpatterns =[

    path('brightlife-test.chargebee.com/api/v2/item_families',createItemFamily.as_view(),name="item-families"),
    

    
]

