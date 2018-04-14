from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2_provider", "0002_08_updates"),
    ]

    operations = [
        migrations.AlterField(
            model_name="application",
            name="user",
            field=models.ForeignKey(related_name="oauth2_provider_application", blank=True, to=settings.AUTH_USER_MODEL, null=True, on_delete=models.CASCADE),
        ),
    ]
