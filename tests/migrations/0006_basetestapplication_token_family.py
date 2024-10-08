# Generated by Django 5.2 on 2024-08-09 16:40

from django.db import migrations, models
from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        ('tests', '0005_basetestapplication_allowed_origins_and_more'),
        migrations.swappable_dependency(oauth2_settings.REFRESH_TOKEN_MODEL)
    ]

    operations = [
        migrations.AddField(
            model_name='samplerefreshtoken',
            name='token_family',
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
    ]
