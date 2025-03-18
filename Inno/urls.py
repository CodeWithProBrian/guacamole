from django.urls import reverse,path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
]
