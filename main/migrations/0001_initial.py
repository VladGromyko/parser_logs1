# Generated by Django 5.0.6 on 2024-05-23 12:26

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='LogEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('datetime', models.DateTimeField()),
                ('event_type', models.CharField(max_length=100)),
                ('auth_type', models.CharField(blank=True, max_length=100, null=True)),
                ('username', models.CharField(blank=True, max_length=100, null=True)),
                ('ip_address', models.CharField(blank=True, max_length=100, null=True)),
                ('port', models.IntegerField(blank=True, null=True)),
                ('session_event', models.CharField(blank=True, max_length=100, null=True)),
                ('session_username', models.CharField(blank=True, max_length=100, null=True)),
                ('session_uid', models.IntegerField(blank=True, null=True)),
                ('session_by_uid', models.IntegerField(blank=True, null=True)),
                ('session_id', models.IntegerField(blank=True, null=True)),
                ('sudo_fail_message', models.TextField(blank=True, null=True)),
                ('connection_closed_username', models.CharField(blank=True, max_length=100, null=True)),
                ('connection_closed_ip', models.CharField(blank=True, max_length=100, null=True)),
                ('connection_closed_port', models.IntegerField(blank=True, null=True)),
                ('received_disconnect_ip', models.CharField(blank=True, max_length=100, null=True)),
                ('received_disconnect_port', models.IntegerField(blank=True, null=True)),
                ('disconnected_username', models.CharField(blank=True, max_length=100, null=True)),
                ('disconnected_ip', models.CharField(blank=True, max_length=100, null=True)),
                ('disconnected_port', models.IntegerField(blank=True, null=True)),
                ('auth_failure_username', models.CharField(blank=True, max_length=100, null=True)),
                ('failed_password_username', models.CharField(blank=True, max_length=100, null=True)),
                ('failed_password_ip', models.CharField(blank=True, max_length=100, null=True)),
                ('failed_password_port', models.IntegerField(blank=True, null=True)),
                ('sshd_listening_address', models.CharField(blank=True, max_length=100, null=True)),
                ('sshd_listening_port', models.IntegerField(blank=True, null=True)),
                ('new_session_logind_id', models.IntegerField(blank=True, null=True)),
                ('new_session_logind_user', models.CharField(blank=True, max_length=100, null=True)),
                ('session_logged_out_id', models.IntegerField(blank=True, null=True)),
                ('session_removed_id', models.IntegerField(blank=True, null=True)),
            ],
        ),
    ]
