from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='dashboard'),
    path('start/', views.start_monitoring, name='start_monitoring'),
    path('stop/', views.stop_monitoring, name='stop_monitoring'),
    path('status/', views.monitoring_status, name='monitoring_status'),
    path('traffic/', views.traffic_summary, name='traffic_summary'),
    path('health/', views.network_health, name='network_health'),
    path('generate-report/', views.generate_report, name='generate_report'),
] 