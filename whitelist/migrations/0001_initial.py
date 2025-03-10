# Generated by Django 5.1.7 on 2025-03-09 21:07

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='WhitelistCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
            options={
                'verbose_name_plural': 'Whitelist Categories',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='WhitelistedApplication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('date_added', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_active', models.BooleanField(default=True)),
                ('categories', models.ManyToManyField(blank=True, related_name='applications', to='whitelist.whitelistcategory')),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='WhitelistedIP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=100, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('date_added', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_active', models.BooleanField(default=True)),
                ('categories', models.ManyToManyField(blank=True, related_name='ip_addresses', to='whitelist.whitelistcategory')),
            ],
            options={
                'verbose_name': 'Whitelisted IP',
                'verbose_name_plural': 'Whitelisted IPs',
                'ordering': ['ip_address'],
            },
        ),
    ]
