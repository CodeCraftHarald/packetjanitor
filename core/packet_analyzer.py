import logging
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Sum, Count
from django.conf import settings
import os

from .models import PacketData, TrafficSummary, MonitoringSession

# Configure logging
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """
    Analyzes captured network packets and generates insights
    """
    def __init__(self):
        self.report_dir = getattr(settings, 'REPORTS_DIR', 'reports/generated')
        os.makedirs(self.report_dir, exist_ok=True)
    
    def analyze_hourly_traffic(self, hour_start=None):
        """Analyze the last hour of traffic and generate a summary"""
        try:
            # Determine time range
            if hour_start is None:
                # Default to the last hour
                now = timezone.now()
                hour_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
            
            hour_end = hour_start + timedelta(hours=1)
            
            # Query packets within the specified hour
            packets = PacketData.objects.filter(
                timestamp__gte=hour_start,
                timestamp__lt=hour_end
            )
            
            if not packets.exists():
                logger.warning(f"No packets found for the specified hour: {hour_start}")
                return None
            
            # Calculate total packets and bytes
            total_packets = packets.count()
            total_bytes = packets.aggregate(Sum('packet_size'))['packet_size__sum'] or 0
            
            # Analyze protocol distribution
            protocol_counts = packets.values('protocol').annotate(
                count=Count('protocol')
            ).order_by('-count')
            
            protocol_distribution = {
                item['protocol'] or 'Unknown': item['count'] 
                for item in protocol_counts
            }
            
            # Analyze application distribution
            app_counts = packets.values('application').annotate(
                count=Count('application')
            ).order_by('-count')
            
            app_distribution = {
                item['application'] or 'Unknown': item['count'] 
                for item in app_counts
            }
            
            # Create traffic summary
            summary = TrafficSummary.objects.create(
                hour_start=hour_start,
                hour_end=hour_end,
                total_packets=total_packets,
                total_bytes=total_bytes,
                protocol_distribution=protocol_distribution,
                application_distribution=app_distribution
            )
            
            # Generate report file
            report_filename = f"report_{hour_start.strftime('%Y-%m-%d_%H-%M-%S')}.pdf"
            report_path = os.path.join(self.report_dir, report_filename)
            
            self._generate_report_file(
                packets, 
                summary, 
                report_path, 
                hour_start, 
                hour_end
            )
            
            # Update summary with report file path
            if os.path.exists(report_path):
                summary.report_file = f"reports/{report_filename}"
                summary.save(update_fields=['report_file'])
            
            return summary
            
        except Exception as e:
            logger.error(f"Error analyzing hourly traffic: {str(e)}")
            return None
    
    def _generate_report_file(self, packets, summary, report_path, hour_start, hour_end):
        """Generate a PDF report file with visualizations and analysis"""
        try:
            # Convert QuerySet to pandas DataFrame for analysis
            packet_list = list(packets.values())
            if not packet_list:
                logger.warning("No packets to generate report")
                return
                
            df = pd.DataFrame(packet_list)
            
            # Create visualizations
            fig, axes = plt.subplots(2, 2, figsize=(12, 10))
            fig.suptitle(f"Network Traffic Report: {hour_start.strftime('%Y-%m-%d %H:%M')} to {hour_end.strftime('%H:%M')}")
            
            # Protocol Distribution
            protocol_series = df['protocol'].value_counts()
            protocol_series.plot.pie(
                ax=axes[0, 0], 
                autopct='%1.1f%%',
                title='Protocol Distribution'
            )
            
            # Application Distribution (top 10)
            app_series = df['application'].value_counts().head(10)
            app_series.plot.bar(
                ax=axes[0, 1],
                title='Top 10 Applications'
            )
            axes[0, 1].set_xticklabels(app_series.index, rotation=45)
            
            # Traffic Volume Over Time
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)
            time_series = df.resample('5Min').size()
            time_series.plot(
                ax=axes[1, 0],
                title='Packets per 5-Minute Interval'
            )
            
            # Packet Size Distribution
            df['packet_size'].plot.hist(
                ax=axes[1, 1],
                bins=20,
                title='Packet Size Distribution'
            )
            
            plt.tight_layout()
            
            # Save the figure to the report file
            plt.savefig(report_path, format='pdf')
            plt.close(fig)
            
            logger.info(f"Report generated: {report_path}")
            
        except Exception as e:
            logger.error(f"Error generating report file: {str(e)}")
    
    def get_recent_traffic_summary(self, minutes=5):
        """Get a summary of traffic from the last few minutes"""
        try:
            start_time = timezone.now() - timedelta(minutes=minutes)
            
            packets = PacketData.objects.filter(timestamp__gte=start_time)
            
            if not packets.exists():
                return {
                    'total_packets': 0,
                    'total_bytes': 0,
                    'protocol_distribution': {},
                    'application_distribution': {},
                    'time_range': f"Last {minutes} minutes"
                }
            
            # Basic statistics
            total_packets = packets.count()
            total_bytes = packets.aggregate(Sum('packet_size'))['packet_size__sum'] or 0
            
            # Protocol distribution
            protocol_counts = packets.values('protocol').annotate(
                count=Count('protocol')
            ).order_by('-count')
            
            protocol_distribution = {
                item['protocol'] or 'Unknown': item['count'] 
                for item in protocol_counts
            }
            
            # Application distribution
            app_counts = packets.values('application').annotate(
                count=Count('application')
            ).order_by('-count')
            
            app_distribution = {
                item['application'] or 'Unknown': item['count'] 
                for item in app_counts
            }
            
            return {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'protocol_distribution': protocol_distribution,
                'application_distribution': app_distribution,
                'time_range': f"Last {minutes} minutes",
                'start_time': start_time,
                'end_time': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Error getting recent traffic summary: {str(e)}")
            return None
    
    def detect_anomalies(self, lookback_hours=24):
        """Detect potential anomalies in network traffic"""
        try:
            # Get baseline from historical data
            baseline_start = timezone.now() - timedelta(hours=lookback_hours)
            
            # Get recent traffic for comparison
            recent_start = timezone.now() - timedelta(minutes=30)
            
            baseline_packets = PacketData.objects.filter(
                timestamp__gte=baseline_start,
                timestamp__lt=recent_start
            )
            
            recent_packets = PacketData.objects.filter(
                timestamp__gte=recent_start
            )
            
            if not baseline_packets.exists() or not recent_packets.exists():
                logger.warning("Insufficient data for anomaly detection")
                return []
            
            anomalies = []
            
            # Check for unusual volume
            baseline_hourly_rate = baseline_packets.count() / lookback_hours
            recent_hourly_rate = recent_packets.count() / 0.5  # 30 minutes to hourly rate
            
            if recent_hourly_rate > baseline_hourly_rate * 2:
                anomalies.append({
                    'type': 'high_traffic_volume',
                    'description': f"Unusual traffic volume detected: {recent_hourly_rate:.1f} packets/hour vs baseline {baseline_hourly_rate:.1f}",
                    'severity': 'medium'
                })
            
            # Check for unusual protocols
            baseline_protocols = Counter([p.protocol for p in baseline_packets])
            recent_protocols = Counter([p.protocol for p in recent_packets])
            
            for protocol, count in recent_protocols.items():
                if protocol not in baseline_protocols and count > 10:
                    anomalies.append({
                        'type': 'new_protocol',
                        'description': f"New protocol detected: {protocol} ({count} packets)",
                        'severity': 'medium'
                    })
            
            # Check for unusual applications
            baseline_apps = Counter([p.application for p in baseline_packets])
            recent_apps = Counter([p.application for p in recent_packets])
            
            for app, count in recent_apps.items():
                if app not in baseline_apps and count > 10:
                    anomalies.append({
                        'type': 'new_application',
                        'description': f"New application detected: {app} ({count} packets)",
                        'severity': 'medium'
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return []
    
    def get_network_health_score(self):
        """Calculate an overall network health score based on various metrics"""
        try:
            # Get recent traffic data
            recent_data = self.get_recent_traffic_summary(minutes=15)
            anomalies = self.detect_anomalies()
            
            # Base score starts at 100
            score = 100
            
            # Deduct points for anomalies
            score -= len(anomalies) * 10
            
            # Analyze application diversity
            app_count = len(recent_data['application_distribution'])
            if app_count > 15:
                score -= 5  # Too many applications might indicate issues
            
            # Check for excessive unknown applications
            unknown_packets = recent_data['application_distribution'].get('Unknown', 0)
            total_packets = recent_data['total_packets'] or 1  # Avoid division by zero
            unknown_ratio = unknown_packets / total_packets
            
            if unknown_ratio > 0.4:
                score -= 15  # High percentage of unknown applications
            
            # Ensure score stays within 0-100 range
            score = max(0, min(score, 100))
            
            return {
                'score': score,
                'status': self._health_score_to_status(score),
                'issues': anomalies,
                'timestamp': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Error calculating network health score: {str(e)}")
            return {
                'score': 50,
                'status': 'unknown',
                'issues': [],
                'timestamp': timezone.now()
            }
    
    def _health_score_to_status(self, score):
        """Convert a numeric health score to a status label"""
        if score >= 90:
            return 'excellent'
        elif score >= 75:
            return 'good'
        elif score >= 60:
            return 'fair'
        elif score >= 40:
            return 'concerning'
        else:
            return 'poor'


# Create a singleton instance
packet_analyzer = PacketAnalyzer() 