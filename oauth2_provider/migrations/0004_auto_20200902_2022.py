import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oauth2_provider', '0003_auto_20201211_1314'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='algorithm',
            field=models.CharField(blank=True, choices=[("", "No OIDC support"), ('RS256', 'RSA with SHA-2 256'), ('HS256', 'HMAC with SHA-2 256')], default='', max_length=5),
        ),
        migrations.AlterField(
            model_name='application',
            name='authorization_grant_type',
            field=models.CharField(choices=[('authorization-code', 'Authorization code'), ('implicit', 'Implicit'), ('password', 'Resource owner password-based'), ('client-credentials', 'Client credentials'), ('openid-hybrid', 'OpenID connect hybrid')], max_length=32),
        ),
        migrations.CreateModel(
            name='IDToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ("jti", models.UUIDField(unique=True, default=uuid.uuid4, editable=False, verbose_name="JWT Token ID")),
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
        migrations.RunSQL(
            # For some reason, the oauth2_provider_idtoken.application_id field is a bigint(20)
            # but it should be int(11) in order to match the type of oauth2_provider_application.id
            # to which it will be made an FK in the next AddField statement.
            #
            # Without this, the migration fails on the next AddField with:
            # django.db.utils.IntegrityError: (1215, 'Cannot add foreign key constraint')
            #
            sql='alter table oauth2_provider_idtoken modify column application_id int(11) NOT NULL;',
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='id_token',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_token', to=oauth2_settings.ID_TOKEN_MODEL),
        ),
        migrations.AddField(
            model_name="grant",
            name="nonce",
            field=models.CharField(blank=True, max_length=255, default=""),
        ),
        migrations.AddField(
            model_name="grant",
            name="claims",
            field=models.TextField(blank=True),
        ),
    ]

# Debug SQL for unapplying a broken 0003 -> 0004 migration, which I had to do
# so. many. times. while patching this because MySQL lacks transactional DDL.
"""
delete from django_migrations where app = 'oauth2_provider' and name = '0004_auto_20200902_2022';
alter table oauth2_provider_grant drop column claims;
alter table oauth2_provider_grant drop column nonce;
alter table oauth2_provider_accesstoken drop column id_token_id;
drop table oauth2_provider_idtoken;
alter table oauth2_provider_application drop column authorization_grant_type;
alter table oauth2_provider_application drop column algorithm;
"""
