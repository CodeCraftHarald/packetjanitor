from django.db import models
from django.utils import timezone

class WhitelistedApplication(models.Model):
    """Model to store whitelisted applications that should be excluded from monitoring"""
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    date_added = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class WhitelistedIP(models.Model):
    """Model to store whitelisted IP addresses that should be excluded from monitoring"""
    ip_address = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    date_added = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['ip_address']
        verbose_name = "Whitelisted IP"
        verbose_name_plural = "Whitelisted IPs"
    
    def __str__(self):
        return self.ip_address


class WhitelistCategory(models.Model):
    """Model to categorize whitelisted applications and IPs"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['name']
        verbose_name_plural = "Whitelist Categories"
    
    def __str__(self):
        return self.name


# Add many-to-many relationship to WhitelistedApplication
WhitelistedApplication.add_to_class(
    'categories', 
    models.ManyToManyField(WhitelistCategory, blank=True, related_name='applications')
)

# Add many-to-many relationship to WhitelistedIP
WhitelistedIP.add_to_class(
    'categories', 
    models.ManyToManyField(WhitelistCategory, blank=True, related_name='ip_addresses')
)
