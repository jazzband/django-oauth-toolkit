# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from oauth2_provider.settings import oauth2_settings
from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accesstoken',
            name='application',
            field=models.ForeignKey(related_name='accesstoken_set', to=oauth2_settings.APPLICATION_MODEL),
        ),
        migrations.AlterField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(null=True, to=settings.AUTH_USER_MODEL, blank=True, related_name='accesstoken_set'),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='access_token',
            field=models.OneToOneField(related_name='refresh_token', to=oauth2_settings.ACCESS_TOKEN_MODEL),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='application',
            field=models.ForeignKey(related_name='refreshtoken_set', to=oauth2_settings.APPLICATION_MODEL),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='user',
            field=models.ForeignKey(related_name='refreshtoken_set', to=settings.AUTH_USER_MODEL),
        ),
    ]
