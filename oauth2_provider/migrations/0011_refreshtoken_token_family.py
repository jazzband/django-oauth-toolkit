# Generated by Django 5.2 on 2024-08-09 16:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0010_application_allowed_origins'),
    ]

    operations = [
        migrations.AddField(
            model_name='refreshtoken',
            name='token_family',
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
    ]
