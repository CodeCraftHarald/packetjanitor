# Generated by Django 5.1.7 on 2025-03-09 21:07

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='MonitoringSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('end_time', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('packets_captured', models.IntegerField(default=0)),
                ('session_description', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'ordering': ['-start_time'],
            },
        ),
        migrations.CreateModel(
            name='TrafficSummary',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('hour_start', models.DateTimeField()),
                ('hour_end', models.DateTimeField()),
                ('total_packets', models.IntegerField(default=0)),
                ('total_bytes', models.BigIntegerField(default=0)),
                ('protocol_distribution', models.JSONField(default=dict)),
                ('application_distribution', models.JSONField(default=dict)),
                ('report_file', models.FileField(blank=True, null=True, upload_to='reports/')),
            ],
            options={
                'ordering': ['-hour_start'],
            },
        ),
        migrations.CreateModel(
            name='PacketData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('source_ip', models.CharField(blank=True, max_length=100, null=True)),
                ('destination_ip', models.CharField(blank=True, max_length=100, null=True)),
                ('protocol', models.CharField(blank=True, max_length=50, null=True)),
                ('packet_size', models.IntegerField(default=0)),
                ('source_port', models.IntegerField(blank=True, null=True)),
                ('destination_port', models.IntegerField(blank=True, null=True)),
                ('packet_summary', models.TextField(blank=True, null=True)),
                ('application', models.CharField(blank=True, max_length=100, null=True)),
                ('is_flagged', models.BooleanField(default=False)),
            ],
            options={
                'ordering': ['-timestamp'],
                'indexes': [models.Index(fields=['timestamp'], name='core_packet_timesta_a945ad_idx'), models.Index(fields=['application'], name='core_packet_applica_dfa4e0_idx'), models.Index(fields=['protocol'], name='core_packet_protoco_e6d633_idx')],
            },
        ),
    ]
