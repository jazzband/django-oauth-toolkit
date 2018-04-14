from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2_provider", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
             model_name="Application",
             name="skip_authorization",
             field=models.BooleanField(default=False),
             preserve_default=True,
        ),
        migrations.AlterField(
            model_name="Application",
            name="user",
            field=models.ForeignKey(related_name="oauth2_provider_application", to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name="AccessToken",
            name="user",
            field=models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, null=True, on_delete=models.CASCADE),
            preserve_default=True,
        ),
    ]
