from django.urls import URLPattern, path

from . import views

from .views import getApplicationDetails, RegisterUserAPIView,CountryList,GetCountryState,AddApplication,ListGender,ListChildStatus,ListChildType,ListRoles,AddBankDetails,getBankDetails,UpdateBankDetails,LogoutView,AddApplicationProfile,UpdateApplicationProfile,UpdateGuardianDetails,UpdateEducationalDetails,UpdateSponsorProfile,getSponsorProfileView,getApplicationDocuments,UpdateApplicationDocument,SponsoredApplications,Login,AddApplicationDocument,SponsorKid,UpdateSponsorApplication,UpdatePassword,GetOTP,verifyOTP,ResendOTP,ChangePassword,OTPMandatorySignup,GetOTPV2,ResendOTPV2,CreateUserView

from django.conf.urls.static import static
from django.conf import  settings

from rest_framework.authtoken import views


urlpatterns =[
    path('brightlife/get/token',views.obtain_auth_token),
    path('brightlife/signin',Login.as_view(),name='login'),
    # path('brightlife/signup',RegisterUserAPIView.as_view(),name="register"),
    path('brightlife/signup',CreateUserView.as_view(),name="register"),

    path('brightlife/logout',LogoutView.as_view(),name="logout"),

    # path('brightlife/request/reset/email', RequestPasswordResetEmail.as_view(),
    #     name="request-reset-email"),
    # path('brightlife/password/reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(), name='password_reset_confirm'),
    # path('brightlife/password/reset/complete', SetNewPasswordAPIView.as_view(),
    #     name='password-reset-complete'),


    path('brightlife/get/otp',GetOTP.as_view(),name="get_otp"),
    path('brightlife/verify/otp',verifyOTP.as_view(),name="verify_otp"),
    path('brightlife/resend/otp',ResendOTP.as_view(),name="resend_otp"),
    path('brightlife/change/password',ChangePassword.as_view(),name="change_password"),
    path('brightlife/update/password',UpdatePassword.as_view(),name="update_password"),

    path('brightlife/v2/get/otp',GetOTPV2.as_view(),name="get_otp"),
    path('brightlife/v2/verify/otp',verifyOTP.as_view(),name="verify_otp"),
    path('brightlife/v2/resend/otp',ResendOTPV2.as_view(),name="resend_otp"),
    path('brightlife/v2/signup',OTPMandatorySignup.as_view(),name="register"),



    # path('add/application',AddApplication.as_view(),name="add_profile"),
    path('brightlife/add/application/profile',AddApplicationProfile.as_view(),name="add_profile"),
    path('brightlife/update/application/profile',UpdateApplicationProfile.as_view(),name="update_application"),
    path('brightlife/update/guardian/details',UpdateGuardianDetails.as_view(),name="update_guardian_details"),
    path('brightlife/update/education/details',UpdateEducationalDetails.as_view(),name="update_education_details"),
    path('brightlife/get/application/details',getApplicationDetails.as_view(),name="application_details"),

    # path('update/education/details',UpdateEducationalDetails.as_view(),name="update_education"),


    path('brightlife/get/bank/details',getBankDetails.as_view(),name="get_bank_details"),
    path('brightlife/add/bank/details',AddBankDetails.as_view(),name="add_bank_details"),
    path('brightlife/update/bank/details',UpdateBankDetails.as_view(),name="update_bank_details"),


    path('brightlife/get/sponsor/profile',getSponsorProfileView.as_view(),name="get_sponsor_view"),
    path('brightlife/update/sponsor/profile',UpdateSponsorProfile.as_view(),name="update_sponsor_profile"),
    path('brightlife/get/sponsor/kids',SponsoredApplications.as_view(),name="get_sponsor_kids"),
    
    path('brightlife/add/application/documents',AddApplicationDocument.as_view(),name="add_application_documents"),
    path('brightlife/get/application/documents',getApplicationDocuments.as_view(),name="get_application_documents"),
    path('brightlife/update/application/documents',UpdateApplicationDocument.as_view(),name="update_application_documents"),


    path('brightlife/sponsor/child',SponsorKid.as_view(),name="sponsor_kid"),
    path('brightlife/update/sponsor/application',UpdateSponsorApplication.as_view(),name="update_sponsor_application"),
    # path('add/application',AddApplicationProfile.as_view(),name="add_application"),

    path('brightlife/list/countries',CountryList.as_view(),name="list_countries"),
    path('brightlife/get/states/by/country',GetCountryState.as_view(),name="country_states"),
    path('brightlife/list/gender',ListGender.as_view(),name="list_gender"),
    path('brightlife/list/child/status',ListChildStatus.as_view(),name="list_child_type"),
    path('brightlife/list/child/type',ListChildType.as_view(),name="list_child_type"),
    path('brightlife/list/roles',ListRoles.as_view(),name="list_roles")

    
]
urlpatterns  += static(settings.STATIC_URL,document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)
