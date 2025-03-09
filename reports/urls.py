from django.urls import path
from . import views

urlpatterns = [
    path('', views.reports_dashboard, name='reports_dashboard'),
    path('list/', views.report_list, name='report_list'),
    path('detail/<int:report_id>/', views.report_detail, name='report_detail'),
    path('download/<int:report_id>/', views.download_report, name='download_report'),
    path('generate/', views.generate_hourly_report, name='generate_hourly_report'),
] 