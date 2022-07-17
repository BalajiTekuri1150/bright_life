from django.urls import URLPattern, path

from . import views

urlpatterns =[
    path('',views.home,name="home"),
    path('education',views.education,name="home"),
    path('about',views.about,name="about"),
]