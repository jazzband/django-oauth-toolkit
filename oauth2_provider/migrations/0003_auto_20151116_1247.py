# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0002_08_updates'),
    ]

    operations = [
        migrations.AddField(
            model_name='refreshtoken',
            name='created',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='refreshtoken',
            name='modified',
            field=models.DateTimeField(default=datetime.datetime(2015, 11, 16, 12, 47, 42, 809872, tzinfo=utc), auto_now=True),
            preserve_default=False,
        ),
    ]
