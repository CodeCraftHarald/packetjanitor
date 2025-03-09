from django.db import models
from django.utils import timezone

class PacketData(models.Model):
    """Model to store captured packet information"""
    timestamp = models.DateTimeField(default=timezone.now)
    source_ip = models.CharField(max_length=100, blank=True, null=True)
    destination_ip = models.CharField(max_length=100, blank=True, null=True)
    protocol = models.CharField(max_length=50, blank=True, null=True)
    packet_size = models.IntegerField(default=0)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    packet_summary = models.TextField(blank=True, null=True)
    application = models.CharField(max_length=100, blank=True, null=True)
    is_flagged = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['application']),
            models.Index(fields=['protocol']),
        ]
    
    def __str__(self):
        return f"{self.timestamp} - {self.source_ip} → {self.destination_ip} ({self.protocol})"


class TrafficSummary(models.Model):
    """Model to store hourly traffic summaries"""
    timestamp = models.DateTimeField(default=timezone.now)
    hour_start = models.DateTimeField()
    hour_end = models.DateTimeField()
    total_packets = models.IntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    protocol_distribution = models.JSONField(default=dict)
    application_distribution = models.JSONField(default=dict)
    report_file = models.FileField(upload_to='reports/', null=True, blank=True)
    
    class Meta:
        ordering = ['-hour_start']
    
    def __str__(self):
        return f"Traffic Summary {self.hour_start.strftime('%Y-%m-%d %H:00')} to {self.hour_end.strftime('%H:00')}"


class MonitoringSession(models.Model):
    """Model to track monitoring sessions"""
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    packets_captured = models.IntegerField(default=0)
    session_description = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        ordering = ['-start_time']
    
    def __str__(self):
        status = "Active" if self.is_active else "Completed"
        return f"{status} Session: {self.start_time.strftime('%Y-%m-%d %H:%M')}"
    
    def duration(self):
        if self.end_time:
            return self.end_time - self.start_time
        return timezone.now() - self.start_time
