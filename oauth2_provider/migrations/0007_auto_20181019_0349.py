# Generated by Django 2.1.1 on 2018-10-19 06:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0006_auto_20171214_2232'),
    ]

    operations = [
        migrations.AddField(
            model_name='grant',
            name='code_challenge',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AddField(
            model_name='grant',
            name='code_challenge_method',
            field=models.CharField(blank=True, choices=[('plain', 'plain'), ('S256', 'S256')], default='', max_length=10),
        ),
    ]
