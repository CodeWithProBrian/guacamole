from django.urls import reverse,path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('about-us/', views.about, name='about'),
    path('contact-us/', views.contact, name='contact'),
]
