from django.urls import URLPattern, path

from . import views

urlpatterns =[
    path('',views.kid_details,name="kid_details"),
    path('<int:id>',views.kid_details,name ="update_kid_details"),
    path('guardian_details',views.guardian_details,name = "guardian_details"),
    path('<int:id>',views.guardian_details,name = "update_guardian_details"),
    path('list_kids',views.listKids,name="listKids"),
    path('education',views.education,name="home"),
    path('about',views.about,name="about"),
    path('new_application',views.home,name="new_application")
]