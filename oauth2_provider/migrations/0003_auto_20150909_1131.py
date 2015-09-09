# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0002_08_updates'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accesstoken',
            name='application',
            field=models.ForeignKey(related_name='accesstoken_set', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        ),
        migrations.AlterField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, null=True, related_name='accesstoken_set'),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='access_token',
            field=models.OneToOneField(to=settings.OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL, related_name='refresh_token'),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='application',
            field=models.ForeignKey(related_name='refreshtoken_set', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='user',
            field=models.ForeignKey(related_name='refreshtoken_set', to=settings.AUTH_USER_MODEL),
        ),
    ]
