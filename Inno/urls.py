from django.urls import reverse,path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('about-us/', views.about, name='about'),
    path('Register/', views.UserRegister, name='register'),
    path('Login/', views.UserLogin, name='login'),
    path('Logout/', views.UserLogout, name='logout'),
    path('contact-us/', views.contact, name='contact'),
    path('profile/', views.profile_view, name='profile'),
    path('refresh-session/', views.refresh_session, name='refresh_session'),
    path('account-settings/', views.account_settings, name='account_settings'),
    path('profile/update/', views.profile_update, name='profile_update'),
    path('contact-success/', views.contact_success, name='success'),
    path('UserForgotPassword/',views.UserForgotPassword, name="forgot-password"),
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('resend-verification/', views.resend_verification, name='resend_verification'),
    path('reset-password/<str:token>/', views.PasswordResetConfirm, name='password_reset_confirm'),
    path('initiate-payment/', views.initiate_payment, name='initiate_payment'),
    path('callback/', views.payment_callback, name='payment_callback'),
    path('stk-status/', views.stk_status_view, name='stk_status'),
    path('BingwaStore/', views.BingwaStore, name="store"),
    path('package/add/', views.add_package, name='add_package'),
    path('package/<int:pk>/edit/', views.edit_package, name='edit_package'),
    path('package/<int:pk>/delete/', views.delete_package, name='delete_package'),
    path('reactivate/<uidb64>/<token>/', views.reactivate_account, name='reactivate_account'),
]
