from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from datetime import datetime, timedelta
import json

from core.models import PacketData, TrafficSummary, MonitoringSession
from core.packet_capture import packet_capture
from core.packet_analyzer import packet_analyzer
from whitelist.models import WhitelistedApplication, WhitelistedIP

@login_required
def home(request):
    """Main dashboard view"""
    # Get monitoring status
    is_monitoring = packet_capture.is_running
    
    # Get recent sessions
    recent_sessions = MonitoringSession.objects.all().order_by('-start_time')[:5]
    
    # Get network health score
    health_score = packet_analyzer.get_network_health_score()
    
    # Get whitelisted items count
    whitelisted_apps_count = WhitelistedApplication.objects.filter(is_active=True).count()
    whitelisted_ips_count = WhitelistedIP.objects.filter(is_active=True).count()
    
    # Get recent traffic summaries
    recent_summaries = TrafficSummary.objects.all().order_by('-hour_start')[:5]
    
    context = {
        'is_monitoring': is_monitoring,
        'recent_sessions': recent_sessions,
        'health_score': health_score,
        'whitelisted_apps_count': whitelisted_apps_count,
        'whitelisted_ips_count': whitelisted_ips_count,
        'recent_summaries': recent_summaries,
    }
    
    return render(request, 'dashboard/home.html', context)

@login_required
def start_monitoring(request):
    """Start the packet capture process"""
    # Get optional filter parameters
    interface = request.POST.get('interface', None)
    filter_str = request.POST.get('filter', None)
    
    # Update whitelist from database
    whitelisted_apps = list(WhitelistedApplication.objects.filter(
        is_active=True
    ).values_list('name', flat=True))
    
    whitelisted_ips = list(WhitelistedIP.objects.filter(
        is_active=True
    ).values_list('ip_address', flat=True))
    
    packet_capture.set_whitelisted_apps(whitelisted_apps)
    packet_capture.set_whitelisted_ips(whitelisted_ips)
    
    # Start monitoring
    result = packet_capture.start_capture(interface, filter_str)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': result})
    
    return redirect('home')

@login_required
def stop_monitoring(request):
    """Stop the packet capture process"""
    result = packet_capture.stop_capture()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': result})
    
    return redirect('home')

@login_required
def monitoring_status(request):
    """Get the current monitoring status"""
    status = packet_capture.get_capture_status()
    return JsonResponse(status)

@login_required
def traffic_summary(request):
    """Display traffic summary page"""
    # Get filter parameters
    time_range = request.GET.get('range', '1h')  # Default to last hour
    app_filter = request.GET.get('app', None)
    protocol_filter = request.GET.get('protocol', None)
    
    # Determine time window
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
    elif time_range == '6h':
        start_time = now - timedelta(hours=6)
    elif time_range == '24h':
        start_time = now - timedelta(hours=24)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    else:
        start_time = now - timedelta(hours=1)
    
    # Build query for packets
    query = PacketData.objects.filter(timestamp__gte=start_time)
    
    if app_filter:
        query = query.filter(application=app_filter)
    
    if protocol_filter:
        query = query.filter(protocol=protocol_filter)
    
    # Get recent packets with pagination
    recent_packets = query.order_by('-timestamp')[:100]
    
    # Get traffic summary
    summary = packet_analyzer.get_recent_traffic_summary(
        minutes=int((now - start_time).total_seconds() / 60)
    )
    
    # Get anomalies
    anomalies = packet_analyzer.detect_anomalies()
    
    context = {
        'recent_packets': recent_packets,
        'summary': summary,
        'anomalies': anomalies,
        'time_range': time_range,
        'app_filter': app_filter,
        'protocol_filter': protocol_filter,
    }
    
    return render(request, 'dashboard/traffic_summary.html', context)

@login_required
def network_health(request):
    """Display network health page"""
    health_score = packet_analyzer.get_network_health_score()
    
    # Get historical health scores (placeholder - would be stored in a real app)
    historical_scores = [
        {'timestamp': timezone.now() - timedelta(hours=i), 'score': 80 + (i % 20)} 
        for i in range(24, 0, -1)
    ]
    
    context = {
        'health_score': health_score,
        'historical_scores': historical_scores,
    }
    
    return render(request, 'dashboard/network_health.html', context)

@csrf_exempt
@login_required
def generate_report(request):
    """Generate a traffic report on demand"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            hour_start_str = data.get('hour_start')
            
            if hour_start_str:
                hour_start = datetime.fromisoformat(hour_start_str)
            else:
                # Default to the last hour
                now = timezone.now()
                hour_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
            
            summary = packet_analyzer.analyze_hourly_traffic(hour_start)
            
            if summary:
                return JsonResponse({
                    'success': True,
                    'report_id': summary.id,
                    'report_url': summary.report_file.url if summary.report_file else None,
                    'total_packets': summary.total_packets,
                    'total_bytes': summary.total_bytes,
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'No data available for the specified time range'
                })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})
