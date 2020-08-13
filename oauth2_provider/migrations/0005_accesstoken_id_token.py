from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0004_idtoken'),
    ]

    operations = [
        migrations.AddField(
            model_name='accesstoken',
            name='id_token',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_token', to=oauth2_settings.ID_TOKEN_MODEL),
        ),
    ]
