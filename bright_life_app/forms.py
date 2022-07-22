from cProfile import label
from django import forms
from .models import Child, ChildDocument,KidDetails,GuardianDetails
from phonenumber_field.formfields import PhoneNumberField


class ChildForm(forms.ModelForm):

    class Meta:
        model = Child
        fields ='__all__'
        labels = {
            'name' :'Name', 
    'birthday' : 'Birthday',
    'email' :'Email',
    'mobile' : 'Mobile',
    'child_type' : 'ChildType',
    'grade' : 'Grade',
    'school_name' : 'School Name',
    'school_address' : 'School Address',
    'hobbies' : 'Hobbies',
    'aspirations' : 'Aspirations',
    'status' : 'Status',
    'profile' : 'Profile'
    }

    def __init__(self, *args, **kwargs):
        super(ChildForm,self).__init__(*args, **kwargs)
        self.fields['child_type'].empty_label = "Select"

class KidDetailsForm(forms.ModelForm):
    class Meta:
        model=KidDetails
        fields = ['name','age','mobile','email','birthday','profile','child_type']
        labels ={
            'name':'Name',
            'age':'Age',
            'email' :'Email',
            'mobile': 'Mobile',
            'birthday' : 'BirthDay',
            'profile' : 'Profile',
            'child_type' : 'Is the Child'
        }

        def __init__(self,*args,**kwargs):
            super(KidDetailsForm,self).__init__(*args,**kwargs)
            self.fields['child_type'].empty_label ="Select"


class GuardianDetailsForm(forms.ModelForm):
    class Meta:
        model:GuardianDetails
        fields = ['kid_id','profession','annual_income','family_member','extra_allowance']
        labels ={
            'kid_id' :'Kid Id',
            'profession' : 'Profession',
            'annual_income' : 'Annual Income',
            'family_member' : 'Family Member',
            'extra_allowance' : 'Extra Allowance'
        }

        def __init__(self,*args,**kwargs):
            super(GuardianDetailsForm,self).__init__(*args,**kwargs)


class EducationalDetailsForm(forms.ModelForm):
    class Meta:
        model : KidDetails
        fields = ['grade','school','school_address','hobbies','aspirations','achievements']
        labels = {
            'grade' : 'Class',
            'school' : 'School Name',
            'school_address' : 'School Address',
            'hobbies' : 'Hobbies',
            'aspirations' : 'Aspirations',
            'achievements' : 'Achievements'
        }

        def __init__(self,*args,**kwargs):
            super(EducationalDetailsForm,self).__init__(*args,**kwargs)

class ChildDocumentForm(forms.ModelForm):
    class Meta:
        model:ChildDocument
        fields = ['name','child_id','document_type','document']
        labels = {
            'name' : 'Name',
            'child_id' : 'Child Id',
            'document_type' : 'Document Type',
            'document' : 'Document'
        }


        def __init__(self,*args,**kwargs):
            super(ChildDocumentForm,self).__init__(*args,**kwargs)
            self.fields['document_type'].empty_label = "Select"



class BankAccountForm(forms.ModelForm):

    class Meta:
        fields = ['kid_id','bank_name','state','postal_code','account_holder','account_number','branch','ifsc']
        labels = {
            'kid_id' : 'Kid Id',
            'bank_name' : 'Bank Name',
            'state' : 'State',
            'postal_code' : 'Postal Code',
            'account_holder' : 'Account Holder',
            'account_number' : 'Account Number',
            'branch' : 'Branch',
            'ifsc' : 'IFSC'
        }

        def __init__(self,*args,**kwargs):
            super(BankAccountForm,self).__init__(*args,**kwargs)
