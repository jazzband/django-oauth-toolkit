# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='refreshtoken',
            name='access_token',
            field=models.OneToOneField(to=settings.OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL, related_name='refresh_token'),
        ),
    ]
