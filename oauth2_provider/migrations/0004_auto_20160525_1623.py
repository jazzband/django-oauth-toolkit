from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2_provider", "0003_auto_20160316_1503"),
    ]

    operations = [
        migrations.AlterField(
            model_name="accesstoken",
            name="token",
            field=models.CharField(unique=True, max_length=255),
        ),
        migrations.AlterField(
            model_name="grant",
            name="code",
            field=models.CharField(unique=True, max_length=255),
        ),
        migrations.AlterField(
            model_name="refreshtoken",
            name="token",
            field=models.CharField(unique=True, max_length=255),
        ),
    ]
