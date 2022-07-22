from email import message
import imp
import re
from xml.dom.minidom import Document
from django.shortcuts import redirect, render

from django.http import Http404, HttpResponse, HttpResponseRedirect
from requests import request

from .forms import BankAccountForm, ChildDocumentForm, ChildForm, KidDetailsForm,GuardianDetailsForm
from .models import *
from django.contrib import messages
from django.core import serializers




def home(request):
    childType = listChildType()
    return render(request,'new_application.html',{'childType':childType})

def about(request):
    return render(request,'footer.html',{'title':'About'})

def education(request):
    return render(request,'education_details.html',{'title':'Educational Details'})

def profile(request,id=0):
    if request.method == 'GET':
        if id ==0:
            form = ChildForm()
        else :
            child = Child.objects.get(id = 1)
            form = ChildForm(instance = child)
        return render(request,'profile.html',{'form':form})
        
    else :
        if id ==0:
            childForm = ChildForm(request.POST)
        else :
            child = Child.objects.get(pk = id)
            form = ChildForm(request.POST,instance = child)
        if childForm.is_valid:
            childForm.save
        return redirect(request,'guardian_details.html')


def listGender():
    return EnumGender.objects.filter(is_active=True).values_list('id','name','gender','description').order_by('id')

def listChildType():
    print(EnumChildType.objects.filter(is_active=True).values_list('id','name','type','description').order_by('id'))
    return EnumChildType.objects.filter(is_active=True).values_list('id','name','type','description').order_by('id')

def listChildStatus():
    return EnumChildStatus.objects.filter(is_active=True).values_list('id','name','status','description').order_by('id')

def addNewApplication():
    if request.method == "POST":
        listChildStatus()

def addApplication(request):
    if request.user.is_authenticated:
        username = request.user.username
    if request.method == 'POST':
        if KidDetails.objects.filter(email = request.POST.get('email')):
            messages.error(request,"Application already exists with the mail",extra_tags="Already Registered")
            return render(request,'navbar.html')
        elif KidDetails.objects.filter(mobile = request.POST.get('mobile')):
            messages.error(request,"Application already exists with the mobile",extra_tags="Already Registered")
            return render(request,'navbar.html')
        else :
            kid = KidDetails(
                name = request.POST.get("name"),
                birthday = request.POST.get("birthday"),
                age = request.POST.get("age"),
                email = request.POST.get("email"),
                phone = request.POST.get("mobile"),
                profile = request.POST.get("profile_img"),
                child_type = request.POST.get("childStatus"), 
                grade = request.POST.get("grade"),
                school = request.POST.get("school"),
                school_address = request.POST.get("school_address"),
                hobbies = request.POST.get("hobbies"),
                aspirations = request.POST.get("aspirations"),
                status = request.POST.get("status"),
                achievements = request.POST.get("achievements"),
                created_by = username,
                last_updated_by = username
            )
            kid.save()

            guardian = GuardianDetails(
                kid_id = kid.pk,
                profession = request.POST.get("profession"),
                annual_income = request.POST.get("annual_income"),
                family_member = request.POST.get("relation"),
                extra_allowance = request.POST.get("extra_allowance"),
                created_by = username,
                last_updated_by = username
            )
            guardian.save()



            files = request.FILES()
            for file in files:
                if request.FILES().get('aadhar').exists() :
                    aadharDocument = request.FILES().get('aadhar')
                    childDocument = ChildDocument(
                    name =  "Aadhar",
                    child_id = kid.pk,
                    document_type = 'aadhar',
                    document = Document(aadharDocument)
                    )
                    childDocument.save()
                elif request.FILES().get('pan').exists() :
                    aadharDocument = request.FILES().get('pan')
                    childDocument = ChildDocument(
                    name = "Pan",
                    child_id = kid.pk,
                    document_type = 'pan',
                    document = Document(aadharDocument)
                    )
                    childDocument.save()

                else :
                    messages.error(request,"No Such Document found")

            bankDetails = BankAccount(
                kid_id = request.POST.get(kid.pk),
                bank_name = request.POST.get('bank_name'),
                state = request.POST.get('state'),
                postal_code = request.POST.get('postal_code'),
                account_holder = request.POST.get('account_holder'),
                account_number = request.POST.get('account_number'),
                branch = request.POST.get('branch'),
                ifsc = request.POST.get('ifsc'),
                created_by = username,
                last_updated_by = username
            )
            bankDetails.save()
            messages.error(request,"Application Added Successfully",extra_tags="Successfully added application")
    else:
        messages.error(request,"Failed to add Application",extra_tags="Failed to add Application")
        return render(request,'applications.html')



def updateKidProfile(request,user_id,id):
        if request.method == "POST":
            kid = KidDetails.objects.filter(pk =id).update(
                name = request.POST.get("name"),
                birthday = request.POST.get("birthday"),
                age = request.POST.get("age"),
                email = request.POST.get("email"),
                phone = request.POST.get("mobile"),
                profile = request.POST.get("profile_img"),
                child_type = request.POST.get("childStatus"), 
                created_by = 'System',
                last_updated_by = 'System'
            )




def addKidDetails(request):
    if request.method == 'POST':
        formData = KidDetailsForm(request.POST)
        if formData.is_valid:
            formData.save()
            messages.success(request,"Successfully Added Kid Details")
            return redirect(request,'guardian_details')
        else :
            messages.error(request,"Something went wrong")

def updateKidDetails(request,id):
    if request.method == 'POST':
        if  KidDetails.objects.all(pk = id).exists():
            existingData = KidDetails.objects.all(pk = id)
            formData = KidDetailsForm(request.POST,instance = existingData)
            if formData.is_valid :
                formData.save()
                messages.success(request,"successfully updated Data")
                return redirect(request,'guardian_details')
            else :
                messages.error(request,"Something went wrong")
        else :
            messages.error(request,'No such kid found to update')
    else :
        messages.error(request,'Something went wrong')


def kid_details(request, id=0):
    if request.method == "GET":
        if id == 0:
            form = KidDetailsForm()
        else:
            try:
                kidDetails = KidDetails.objects.get(pk=id)
                form = KidDetailsForm(instance=kidDetails)
            except KidDetails.DoesNotExist:
                raise Http404("No Kid matches the given id.")  
        return render(request, "profile.html", {'form': form})
    else:
        if id == 0:
            form = KidDetailsForm(request.POST)
        else:
            kidDetails = KidDetails.objects.get(pk=id)
            form = KidDetailsForm(request.POST,instance= kidDetails)
        if form.is_valid():
            form.save()
        # return redirect(request,'guardian_details.html')
        return HttpResponse("Success")


def guardian_details(request,id):
    if request.method == "GET":
        if id == 0:
            form = GuardianDetailsForm()
        else :
            guardianDetails = GuardianDetails.objects.get(pk = id)
            if guardianDetails.exists():
                guardianForm = GuardianDetailsForm(instance = guardianDetails)
            else :
                messages.error(request,"No Guardian Details Found")
        return render(request,"education_details.html",{'form':guardianForm})
    else :
        if id ==0:
            guardianDetails = GuardianDetailsForm(request.POST)
        else :
            existingDetails = GuardianDetails.objects.filter(pk = id)
            if existingDetails.exists():
                messages.error("No Such Guardian found to update")
            else :
                guardianDetails = GuardianDetailsForm(request.POST,instance=existingDetails)
        if guardianDetails.is_valid :
            guardianDetails.save()
        return redirect(request,'education_details.html')




def child_documents(request,id=0):
    if request.method == "GET":
        if id ==0:
            form = ChildDocumentForm()
        else:
            return


def bank_details(request,id=0):
    if request.method == "GET":
        if id ==0:
            form = BankAccountForm()
        else :
            try:
                bankDetails = BankAccount.objects.get(pk =id)
                form = BankAccountForm(instance = bankDetails)
            except BankAccount.DoesNotExist:
                raise Http404("No BankAccount matches the given id.")  
        return render(request,"bank_details.html",{'form':form})
    else :
        if id == 0:
            bankDetails = BankAccountForm(request.POST)
        else :
            try :
                existingData = BankAccount.objects.get(pk =id)
                bankDetails = BankAccountForm(request.POST,instance=existingData)
            except BankAccount.DoesNotExist :
                raise Http404("No bank account details found to update")
        return HttpResponse("Success")



def getKidById(request,id):
    if request.method == 'GET':
        kidDetails = KidDetails.objects.filter(pk = id)
        if kidDetails.exists() :
            return render(request,'profile.html',{'kidDetails':kidDetails})


def listKids(request):
    response = Child.objects.all()
    data = serializers.serialize('json', response)
    return render(request,'applications.html',{'response':data})



