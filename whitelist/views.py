from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from .models import WhitelistedApplication, WhitelistedIP, WhitelistCategory
from core.packet_capture import packet_capture

@login_required
def whitelist_home(request):
    """Main whitelist dashboard"""
    context = {
        'title': 'Whitelist Management'
    }
    return render(request, 'whitelist/home.html', context)

@login_required
def whitelisted_apps(request):
    """List all whitelisted applications"""
    apps = WhitelistedApplication.objects.all().order_by('name')
    
    # Filter by category if specified
    category_id = request.GET.get('category')
    if category_id:
        category = get_object_or_404(WhitelistCategory, id=category_id)
        apps = apps.filter(categories=category)
    
    # Filter by active status if specified
    status = request.GET.get('status')
    if status == 'active':
        apps = apps.filter(is_active=True)
    elif status == 'inactive':
        apps = apps.filter(is_active=False)
    
    categories = WhitelistCategory.objects.all()
    
    context = {
        'apps': apps,
        'categories': categories,
        'selected_category': category_id,
        'selected_status': status,
    }
    
    return render(request, 'whitelist/apps.html', context)

@login_required
def whitelisted_ips(request):
    """List all whitelisted IP addresses"""
    ips = WhitelistedIP.objects.all().order_by('ip_address')
    
    # Filter by category if specified
    category_id = request.GET.get('category')
    if category_id:
        category = get_object_or_404(WhitelistCategory, id=category_id)
        ips = ips.filter(categories=category)
    
    # Filter by active status if specified
    status = request.GET.get('status')
    if status == 'active':
        ips = ips.filter(is_active=True)
    elif status == 'inactive':
        ips = ips.filter(is_active=False)
    
    categories = WhitelistCategory.objects.all()
    
    context = {
        'ips': ips,
        'categories': categories,
        'selected_category': category_id,
        'selected_status': status,
    }
    
    return render(request, 'whitelist/ips.html', context)

@login_required
def add_app(request):
    """Add a new whitelisted application"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        is_active = request.POST.get('is_active') == 'on'
        category_ids = request.POST.getlist('categories')
        
        if not name:
            messages.error(request, "Application name is required")
            return redirect('add_whitelisted_app')
        
        # Check if app already exists
        if WhitelistedApplication.objects.filter(name=name).exists():
            messages.error(request, f"Application '{name}' is already whitelisted")
            return redirect('whitelisted_apps')
        
        # Create new app
        app = WhitelistedApplication.objects.create(
            name=name,
            description=description,
            is_active=is_active
        )
        
        # Add categories
        if category_ids:
            categories = WhitelistCategory.objects.filter(id__in=category_ids)
            app.categories.set(categories)
        
        messages.success(request, f"Added '{name}' to whitelist")
        
        # Update running capture if active
        if packet_capture.is_running:
            whitelisted_apps = list(WhitelistedApplication.objects.filter(
                is_active=True
            ).values_list('name', flat=True))
            packet_capture.set_whitelisted_apps(whitelisted_apps)
        
        return redirect('whitelisted_apps')
    
    # GET request
    categories = WhitelistCategory.objects.all()
    
    context = {
        'categories': categories,
    }
    
    return render(request, 'whitelist/add_app.html', context)

@login_required
def add_ip(request):
    """Add a new whitelisted IP address"""
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        description = request.POST.get('description', '')
        is_active = request.POST.get('is_active') == 'on'
        category_ids = request.POST.getlist('categories')
        
        if not ip_address:
            messages.error(request, "IP address is required")
            return redirect('add_whitelisted_ip')
        
        # Check if IP already exists
        if WhitelistedIP.objects.filter(ip_address=ip_address).exists():
            messages.error(request, f"IP address '{ip_address}' is already whitelisted")
            return redirect('whitelisted_ips')
        
        # Create new IP
        ip = WhitelistedIP.objects.create(
            ip_address=ip_address,
            description=description,
            is_active=is_active
        )
        
        # Add categories
        if category_ids:
            categories = WhitelistCategory.objects.filter(id__in=category_ids)
            ip.categories.set(categories)
        
        messages.success(request, f"Added '{ip_address}' to whitelist")
        
        # Update running capture if active
        if packet_capture.is_running:
            whitelisted_ips = list(WhitelistedIP.objects.filter(
                is_active=True
            ).values_list('ip_address', flat=True))
            packet_capture.set_whitelisted_ips(whitelisted_ips)
        
        return redirect('whitelisted_ips')
    
    # GET request
    categories = WhitelistCategory.objects.all()
    
    context = {
        'categories': categories,
    }
    
    return render(request, 'whitelist/add_ip.html', context)

@login_required
def edit_app(request, app_id):
    """Edit an existing whitelisted application"""
    app = get_object_or_404(WhitelistedApplication, id=app_id)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        is_active = request.POST.get('is_active') == 'on'
        category_ids = request.POST.getlist('categories')
        
        if not name:
            messages.error(request, "Application name is required")
            return redirect('edit_whitelisted_app', app_id=app_id)
        
        # Check if name already exists (excluding this app)
        if (WhitelistedApplication.objects.filter(name=name)
                .exclude(id=app_id).exists()):
            messages.error(request, f"Another application with name '{name}' already exists")
            return redirect('edit_whitelisted_app', app_id=app_id)
        
        # Update app
        app.name = name
        app.description = description
        app.is_active = is_active
        app.save()
        
        # Update categories
        if category_ids:
            categories = WhitelistCategory.objects.filter(id__in=category_ids)
            app.categories.set(categories)
        else:
            app.categories.clear()
        
        messages.success(request, f"Updated '{name}' in whitelist")
        
        # Update running capture if active
        if packet_capture.is_running:
            whitelisted_apps = list(WhitelistedApplication.objects.filter(
                is_active=True
            ).values_list('name', flat=True))
            packet_capture.set_whitelisted_apps(whitelisted_apps)
        
        return redirect('whitelisted_apps')
    
    # GET request
    categories = WhitelistCategory.objects.all()
    selected_categories = app.categories.all()
    
    context = {
        'app': app,
        'categories': categories,
        'selected_categories': selected_categories,
    }
    
    return render(request, 'whitelist/edit_app.html', context)

@login_required
def edit_ip(request, ip_id):
    """Edit an existing whitelisted IP address"""
    ip = get_object_or_404(WhitelistedIP, id=ip_id)
    
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        description = request.POST.get('description', '')
        is_active = request.POST.get('is_active') == 'on'
        category_ids = request.POST.getlist('categories')
        
        if not ip_address:
            messages.error(request, "IP address is required")
            return redirect('edit_whitelisted_ip', ip_id=ip_id)
        
        # Check if IP already exists (excluding this one)
        if (WhitelistedIP.objects.filter(ip_address=ip_address)
                .exclude(id=ip_id).exists()):
            messages.error(request, f"Another entry with IP '{ip_address}' already exists")
            return redirect('edit_whitelisted_ip', ip_id=ip_id)
        
        # Update IP
        ip.ip_address = ip_address
        ip.description = description
        ip.is_active = is_active
        ip.save()
        
        # Update categories
        if category_ids:
            categories = WhitelistCategory.objects.filter(id__in=category_ids)
            ip.categories.set(categories)
        else:
            ip.categories.clear()
        
        messages.success(request, f"Updated '{ip_address}' in whitelist")
        
        # Update running capture if active
        if packet_capture.is_running:
            whitelisted_ips = list(WhitelistedIP.objects.filter(
                is_active=True
            ).values_list('ip_address', flat=True))
            packet_capture.set_whitelisted_ips(whitelisted_ips)
        
        return redirect('whitelisted_ips')
    
    # GET request
    categories = WhitelistCategory.objects.all()
    selected_categories = ip.categories.all()
    
    context = {
        'ip': ip,
        'categories': categories,
        'selected_categories': selected_categories,
    }
    
    return render(request, 'whitelist/edit_ip.html', context)

@login_required
def delete_app(request, app_id):
    """Delete a whitelisted application"""
    app = get_object_or_404(WhitelistedApplication, id=app_id)
    
    if request.method == 'POST':
        name = app.name
        app.delete()
        
        messages.success(request, f"Removed '{name}' from whitelist")
        
        # Update running capture if active
        if packet_capture.is_running:
            whitelisted_apps = list(WhitelistedApplication.objects.filter(
                is_active=True
            ).values_list('name', flat=True))
            packet_capture.set_whitelisted_apps(whitelisted_apps)
        
        return redirect('whitelisted_apps')
    
    context = {
        'app': app,
    }
    
    return render(request, 'whitelist/delete_app.html', context)

@login_required
def delete_ip(request, ip_id):
    """Delete a whitelisted IP address"""
    ip = get_object_or_404(WhitelistedIP, id=ip_id)
    
    if request.method == 'POST':
        ip_address = ip.ip_address
        ip.delete()
        
        messages.success(request, f"Removed '{ip_address}' from whitelist")
        
        # Update running capture if active
        if packet_capture.is_running:
            whitelisted_ips = list(WhitelistedIP.objects.filter(
                is_active=True
            ).values_list('ip_address', flat=True))
            packet_capture.set_whitelisted_ips(whitelisted_ips)
        
        return redirect('whitelisted_ips')
    
    context = {
        'ip': ip,
    }
    
    return render(request, 'whitelist/delete_ip.html', context)

@login_required
def categories(request):
    """List all whitelist categories"""
    all_categories = WhitelistCategory.objects.all().order_by('name')
    
    context = {
        'categories': all_categories,
    }
    
    return render(request, 'whitelist/categories.html', context)

@login_required
def add_category(request):
    """Add a new whitelist category"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        
        if not name:
            messages.error(request, "Category name is required")
            return redirect('add_whitelist_category')
        
        # Check if category already exists
        if WhitelistCategory.objects.filter(name=name).exists():
            messages.error(request, f"Category '{name}' already exists")
            return redirect('whitelist_categories')
        
        # Create new category
        WhitelistCategory.objects.create(
            name=name,
            description=description
        )
        
        messages.success(request, f"Added category '{name}'")
        return redirect('whitelist_categories')
    
    return render(request, 'whitelist/add_category.html')

@login_required
def edit_category(request, category_id):
    """Edit an existing whitelist category"""
    category = get_object_or_404(WhitelistCategory, id=category_id)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        
        if not name:
            messages.error(request, "Category name is required")
            return redirect('edit_whitelist_category', category_id=category_id)
        
        # Check if name already exists (excluding this category)
        if (WhitelistCategory.objects.filter(name=name)
                .exclude(id=category_id).exists()):
            messages.error(request, f"Another category with name '{name}' already exists")
            return redirect('edit_whitelist_category', category_id=category_id)
        
        # Update category
        category.name = name
        category.description = description
        category.save()
        
        messages.success(request, f"Updated category '{name}'")
        return redirect('whitelist_categories')
    
    context = {
        'category': category,
    }
    
    return render(request, 'whitelist/edit_category.html', context)

@login_required
def delete_category(request, category_id):
    """Delete a whitelist category"""
    category = get_object_or_404(WhitelistCategory, id=category_id)
    
    if request.method == 'POST':
        name = category.name
        
        # Check if category is in use
        apps_count = category.applications.count()
        ips_count = category.ip_addresses.count()
        
        if apps_count > 0 or ips_count > 0:
            messages.error(
                request, 
                f"Cannot delete category '{name}' because it is used by "
                f"{apps_count} applications and {ips_count} IP addresses"
            )
            return redirect('whitelist_categories')
        
        category.delete()
        messages.success(request, f"Deleted category '{name}'")
        return redirect('whitelist_categories')
    
    # Count related items
    apps_count = category.applications.count()
    ips_count = category.ip_addresses.count()
    
    context = {
        'category': category,
        'apps_count': apps_count,
        'ips_count': ips_count,
    }
    
    return render(request, 'whitelist/delete_category.html', context)
