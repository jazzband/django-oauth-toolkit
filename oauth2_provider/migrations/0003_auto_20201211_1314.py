# Generated by Django 3.1.4 on 2020-12-11 13:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0002_auto_20190406_1805'),
    ]

    operations = [
        migrations.AlterField(
            model_name='grant',
            name='redirect_uri',
            field=models.TextField(),
        ),
    ]
