from django.urls import path
from . import views

urlpatterns = [
    path('', views.whitelist_home, name='whitelist_home'),
    path('apps/', views.whitelisted_apps, name='whitelisted_apps'),
    path('ips/', views.whitelisted_ips, name='whitelisted_ips'),
    path('apps/add/', views.add_app, name='add_whitelisted_app'),
    path('ips/add/', views.add_ip, name='add_whitelisted_ip'),
    path('apps/edit/<int:app_id>/', views.edit_app, name='edit_whitelisted_app'),
    path('ips/edit/<int:ip_id>/', views.edit_ip, name='edit_whitelisted_ip'),
    path('apps/delete/<int:app_id>/', views.delete_app, name='delete_whitelisted_app'),
    path('ips/delete/<int:ip_id>/', views.delete_ip, name='delete_whitelisted_ip'),
    path('categories/', views.categories, name='whitelist_categories'),
    path('categories/add/', views.add_category, name='add_whitelist_category'),
    path('categories/edit/<int:category_id>/', views.edit_category, name='edit_whitelist_category'),
    path('categories/delete/<int:category_id>/', views.delete_category, name='delete_whitelist_category'),
] 