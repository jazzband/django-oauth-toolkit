# -*- coding: utf-8 -*-
# Generated by Django 1.10b1 on 2016-06-29 15:18
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0003_auto_20160316_1503'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='allowed_scopes',
            field=models.TextField(blank=True, help_text='List of allowed scopes for this application, space separated'),
        ),
    ]
