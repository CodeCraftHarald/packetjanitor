from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, Http404
from django.conf import settings
from django.utils import timezone
import os
from datetime import datetime, timedelta

from core.models import TrafficSummary
from core.packet_analyzer import packet_analyzer

@login_required
def report_list(request):
    """Display a list of all generated reports"""
    # Get filter parameters
    days = request.GET.get('days', '7')
    try:
        days = int(days)
    except ValueError:
        days = 7
    
    # Calculate time window
    start_date = timezone.now() - timedelta(days=days)
    
    # Query reports
    reports = TrafficSummary.objects.filter(
        hour_start__gte=start_date
    ).order_by('-hour_start')
    
    context = {
        'reports': reports,
        'days_filter': days,
    }
    
    return render(request, 'reports/list.html', context)

@login_required
def report_detail(request, report_id):
    """Display details of a specific report"""
    report = get_object_or_404(TrafficSummary, id=report_id)
    
    context = {
        'report': report,
        'protocol_data': report.protocol_distribution,
        'application_data': report.application_distribution,
    }
    
    return render(request, 'reports/detail.html', context)

@login_required
def download_report(request, report_id):
    """Download a report file"""
    report = get_object_or_404(TrafficSummary, id=report_id)
    
    if not report.report_file:
        raise Http404("Report file not found")
    
    file_path = os.path.join(settings.MEDIA_ROOT, report.report_file.name)
    
    if not os.path.exists(file_path):
        raise Http404("Report file not found")
    
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
        return response

@login_required
def generate_hourly_report(request):
    """Generate a report for the last hour"""
    # Get the last hour
    now = timezone.now()
    hour_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    
    # Generate report
    summary = packet_analyzer.analyze_hourly_traffic(hour_start)
    
    if summary:
        return JsonResponse({
            'success': True,
            'report_id': summary.id,
            'hour': hour_start.strftime('%Y-%m-%d %H:%M'),
            'total_packets': summary.total_packets,
        })
    else:
        return JsonResponse({
            'success': False,
            'error': 'Failed to generate report',
        })

@login_required
def reports_dashboard(request):
    """Display reports dashboard"""
    # Get recent reports
    recent_reports = TrafficSummary.objects.all().order_by('-hour_start')[:5]
    
    # Get report stats
    total_reports = TrafficSummary.objects.count()
    today_reports = TrafficSummary.objects.filter(
        hour_start__date=timezone.now().date()
    ).count()
    
    # Get the hours with most traffic (top 5)
    top_traffic_hours = TrafficSummary.objects.all().order_by('-total_packets')[:5]
    
    context = {
        'recent_reports': recent_reports,
        'total_reports': total_reports,
        'today_reports': today_reports,
        'top_traffic_hours': top_traffic_hours,
    }
    
    return render(request, 'reports/dashboard.html', context)
