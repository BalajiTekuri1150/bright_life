from django.urls import URLPattern, path

from . import views

from .views import CheckEmail, ListDocumentTypes, UpdateGuardianProfile, UpdateSponsorDetails, getApplicationDetails, RegisterUserAPIView,CountryList,GetCountryState,AddApplication,ListGender,ListChildStatus,ListChildType,ListRoles,AddBankDetails,getBankDetails,UpdateBankDetails,LogoutView,AddApplicationProfile,UpdateApplicationProfile,UpdateGuardianDetails,UpdateEducationalDetails,UpdateSponsorProfile, getGuardianProfileView,getSponsorProfileView,getApplicationDocuments,UpdateApplicationDocument,SponsoredApplications,Login,AddApplicationDocument,SponsorKid,UpdateSponsorship,UpdatePassword,GetOTP,verifyOTP,ResendOTP,ChangePassword,OTPMandatorySignup,GetOTPV2,ResendOTPV2,CreateUserView,RemoveApplicationDocuments,BulkInsertApplicationDocument,createCustomer,updateSubscriptionDetails,ListDonationPlans,CreateCheckoutSession,UpdateStripeSubscriptionDetails,GoogleSignup, GoogleSignIn

from django.conf.urls.static import static
from django.conf import  settings

from rest_framework.authtoken import views

from django.urls import path,include

from .chargebee_utils import *


urlpatterns =[
    path('brightlife-test.chargebee.com/api/v2/item_families',createItemFamily.as_view(),name="item-families"),
    path('brightlife-test.chargebee.com/api/v2/items',createItem.as_view(),name="items"),
    path('brightlife-test.chargebee.com/api/v2/get/items/list',getItemsList.as_view(),name="items"),
    path('brightlife-test.chargebee.com/api/v2/item_prices',createItemPrice.as_view(),name="create-item-price"),
    path('brightlife-test.chargebee.com/api/v2/update/item_prices',updateItemPrice.as_view(),name="update-item-price"),
    path('brightlife-test.chargebee.com/api/v2/list/customers',listCustomers.as_view(),name="list-customers"),
    path('brightlife-test.chargebee.com/api/v2/get/checkout',getCheckoutPage.as_view(),name="get-checkout-page"),
    path('brightlife-test.chargebee.com/api/v2/get/item/prices',getItemPricesList.as_view(),name="get-checkout-page"),
    path('brightlife-test.chargebee.com/api/v2/create/customer',createCustomer.as_view(),name="get-checkout-page"),
    path('brightlife-test.chargebee.com/api/v2/update/subscription/details',updateSubscriptionDetails.as_view(),name="get-checkout-page"),

    path('brightlife/google/signup/', GoogleSignup.as_view(), name='google_signup'),
    path('brightlife/google/login/', GoogleSignIn.as_view(), name='google_login'),

    
    path('brightlife/get/token',views.obtain_auth_token),
    path('brightlife/signin',Login.as_view(),name='login'),
    # path('brightlife/signup',RegisterUserAPIView.as_view(),name="register"),
    path('brightlife/signup',CreateUserView.as_view(),name="register"),
    #path('brightlife/create',CreateView.as_view(),name="summy"),

    path('brightlife/logout',LogoutView.as_view(),name="logout"),

    # path('brightlife/request/reset/email', RequestPasswordResetEmail.as_view(),
    #     name="request-reset-email"),
    # path('brightlife/password/reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(), name='password_reset_confirm'),
    # path('brightlife/password/reset/complete', SetNewPasswordAPIView.as_view(),
    #     name='password-reset-complete'),
    
    
    path('brightlife/list/donations',ListDonationPlans.as_view(),name="get_otp"),
    path('brightlife/create/checkout',CreateCheckoutSession.as_view(),name="get_otp"),
    path('brightlife/update/subscription/details',UpdateStripeSubscriptionDetails.as_view(),name="update-subscription-details"),
    


    path('brightlife/get/otp',GetOTP.as_view(),name="get_otp"),
    path('brightlife/verify/otp',verifyOTP.as_view(),name="verify_otp"),
    path('brightlife/resend/otp',ResendOTP.as_view(),name="resend_otp"),
    path('brightlife/change/password',ChangePassword.as_view(),name="change_password"),
    path('brightlife/update/password',UpdatePassword.as_view(),name="update_password"),

    path('brightlife/v2/get/otp',GetOTPV2.as_view(),name="get_otp"),
    path('brightlife/v2/verify/otp',verifyOTP.as_view(),name="verify_otp"),
    path('brightlife/v2/resend/otp',ResendOTPV2.as_view(),name="resend_otp"),
    path('brightlife/v2/signup',OTPMandatorySignup.as_view(),name="register"),

    path('brightlife/check/email',CheckEmail.as_view(),name='check_email'),

    # path('add/application',AddApplication.as_view(),name="profile"),
    path('brightlife/add/application/profile',AddApplicationProfile.as_view(),name="add_profile"),
    path('brightlife/update/application/profile',UpdateApplicationProfile.as_view(),name="update_application"),
    path('brightlife/update/guardian/details',UpdateGuardianDetails.as_view(),name="update_guardian_details"),
    path('brightlife/update/education/details',UpdateEducationalDetails.as_view(),name="update_education_details"),
    path('brightlife/get/application/details',getApplicationDetails.as_view(),name="application_details"),

    # path('update/education/details',UpdateEducationalDetails.as_view(),name="update_education"),


    path('brightlife/get/bank/details',getBankDetails.as_view(),name="get_bank_details"),
    path('brightlife/add/bank/details',AddBankDetails.as_view(),name="add_bank_details"),
    path('brightlife/update/bank/details',UpdateBankDetails.as_view(),name="update_bank_details"),

  
    path('brightlife/update/sponsor/details',UpdateSponsorDetails.as_view(),name="update_sponsor_details"),
    path('brightlife/get/sponsor/profile',getSponsorProfileView.as_view(),name="get_sponsor_view"),
    path('brightlife/update/sponsor/profile',UpdateSponsorProfile.as_view(),name="update_sponsor_profile"),
    path('brightlife/get/sponsor/kids',SponsoredApplications.as_view(),name="get_sponsor_kids"),

    path('brightlife/get/guardian/profile',getGuardianProfileView.as_view(),name="get_guardian_view"),
    path('brightlife/update/guardian/profile',UpdateGuardianProfile.as_view(),name="update_guardian_profile"),
    
    path('brightlife/add/application/documents',AddApplicationDocument.as_view(),name="add_application_documents"),
    path('brightlife/get/application/documents',getApplicationDocuments.as_view(),name="get_application_documents"),
    path('brightlife/update/application/documents',UpdateApplicationDocument.as_view(),name="update_application_documents"),
    path('brightlife/remove/application/documents',RemoveApplicationDocuments.as_view(),name="update_application_documents"),
    path('brightlife/bulk/insert/application/documents',BulkInsertApplicationDocument.as_view(),name="add_application_documents"),


    path('brightlife/sponsor/child',SponsorKid.as_view(),name="sponsor_kid"),
    path('brightlife/update/sponsor/application',UpdateSponsorship.as_view(),name="update_sponsor_application"),
    # path('add/application',AddApplicationProfile.as_view(),name="add_application"),

    path('brightlife/list/countries',CountryList.as_view(),name="list_countries"),
    path('brightlife/get/states/by/country',GetCountryState.as_view(),name="country_states"),
    path('brightlife/list/gender',ListGender.as_view(),name="list_gender"),
    path('brightlife/list/child/status',ListChildStatus.as_view(),name="list_child_type"),
    path('brightlife/list/child/type',ListChildType.as_view(),name="list_child_type"),
    path('brightlife/list/roles',ListRoles.as_view(),name="list_roles"),
    path('brightlife/list/document/types',ListDocumentTypes.as_view(),name="list_document_types")
    

    
]
urlpatterns  += static(settings.STATIC_URL,document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)
