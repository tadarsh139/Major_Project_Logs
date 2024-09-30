from django.urls import path
from .views import index,check_security_logs

urlpatterns = [
    path('', index, name='index'),
    path('check-logs/', check_security_logs, name='check_security_logs'),
]
