from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oauth2_provider', '0003_auto_20190413_2007'),
    ]

    operations = [
        migrations.CreateModel(
            name='IDToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('token', models.TextField(unique=True)),
                ('expires', models.DateTimeField()),
                ('scope', models.TextField(blank=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('application', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=oauth2_settings.APPLICATION_MODEL)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='oauth2_provider_idtoken', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'swappable': 'OAUTH2_PROVIDER_ID_TOKEN_MODEL',
            },
        ),
    ]
