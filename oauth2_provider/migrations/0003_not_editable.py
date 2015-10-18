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
            model_name='Application',
            name='skip_authorization',
            field=models.BooleanField(editable=False, default=False),
        ),
        migrations.AlterField(
            model_name='Application',
            name='user',
            field=models.ForeignKey(related_name='oauth2_provider_application', editable=False, to=settings.AUTH_USER_MODEL),
        ),
    ]
