# Generated by Django 3.2.25 on 2024-08-08 22:47

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('tests', '0006_basetestapplication_token_family'),
    ]

    operations = [
        migrations.CreateModel(
            name='LocalIDToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('jti', models.UUIDField(default=uuid.uuid4, editable=False, unique=True, verbose_name='JWT Token ID')),
                ('expires', models.DateTimeField()),
                ('scope', models.TextField(blank=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('application', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='tests_localidtoken', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
