import imp
import re
from django.shortcuts import render

from django.http import HttpResponse
from .models import Kid
from django.contrib import messages



# postss = [
#     {
#         'author':"Author1",
#         'title': 'Blog1',
#         'content':'First Content'
#     }
# ]
# Create your views here.
def home(request):
    # return render(request,'profile.html')
    # context ={
    #     'posts':postss,
    #     'title':'Home'
    # }
    return render(request,'profile.html',{'title':'My Profile'})

def about(request):
    return render(request,'about.html',{'title':'About'})

def education(request):
    return render(request,'education_details.html',{'title':'Educational Details'})

def updateKid(request):
    if request.method == 'POST':
        if Kid.objects.filter(id = request.POST.get("id")):
            messages.error(request,"Already Registered",extra_tags="Already Registered")
            return render(request,'navbar.html')
        else :
            kid1 = Kid(
                name = request.POST.get("name"),
                birthday = request.POST.get("birthday"),
                age = request.POST.get("age"),
                email = request.POST.get("email"),
                phone = request.POST.get("mobile")
            )
            kid1.save()
            messages.error(request,"Successfully Added Kid",extra_tags="Successfully added Kid")
            return render(request,'applications.html')
    else:
        messages.error(request,"Failed to add Kid",extra_tags="Failed to add Kid")
        return render(request,'applications.html')


