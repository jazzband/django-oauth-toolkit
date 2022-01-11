from datetime import timedelta
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)


Application = get_application_model()
AccesstokenModel = get_access_token_model()
RefreshTokenModel = get_refresh_token_model()
GrantModel = get_grant_model()


class CreateApplicationTest(TestCase):
    def test_command_creates_application(self):
        output = StringIO()
        self.assertEqual(Application.objects.count(), 0)
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            stdout=output,
        )
        self.assertEqual(Application.objects.count(), 1)
        self.assertIn("New application created successfully", output.getvalue())

    def test_missing_required_args(self):
        self.assertEqual(Application.objects.count(), 0)
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "createapplication",
                "--redirect-uris=http://example.com http://example2.com",
            )

        self.assertIn("client_type", ctx.exception.args[0])
        self.assertIn("authorization_grant_type", ctx.exception.args[0])
        self.assertEqual(Application.objects.count(), 0)

    def test_command_creates_application_with_skipped_auth(self):
        self.assertEqual(Application.objects.count(), 0)
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--skip-authorization",
        )
        app = Application.objects.get()

        self.assertTrue(app.skip_authorization)

    def test_application_created_normally_with_no_skipped_auth(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
        )
        app = Application.objects.get()

        self.assertFalse(app.skip_authorization)

    def test_application_created_with_name(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--name=TEST",
        )
        app = Application.objects.get()

        self.assertEqual(app.name, "TEST")

    def test_application_created_with_client_secret(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--client-secret=SECRET",
        )
        app = Application.objects.get()

        self.assertEqual(app.client_secret, "SECRET")

    def test_application_created_with_client_id(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--client-id=someId",
        )
        app = Application.objects.get()

        self.assertEqual(app.client_id, "someId")

    def test_application_created_with_user(self):
        User = get_user_model()
        user = User.objects.create()
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--user=%s" % user.pk,
        )
        app = Application.objects.get()

        self.assertEqual(app.user, user)

    def test_validation_failed_message(self):
        output = StringIO()
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--user=783",
            stdout=output,
        )

        self.assertIn("user", output.getvalue())
        self.assertIn("783", output.getvalue())
        self.assertIn("does not exist", output.getvalue())


class ClearTokensTest(TestCase):
    def setUp(self):
        now = timezone.now()
        earlier = now - timedelta(seconds=100)
        later = now + timedelta(seconds=100)
        UserModel = get_user_model()
        user = UserModel.objects.create()

        app = Application.objects.create(
            client_type="confidential",
            authorization_grant_type="client-credentials",
            name="The App",
        )
        for i in range(100):
            old = AccesstokenModel.objects.create(token="old access token {}".format(i), expires=earlier)
            new = AccesstokenModel.objects.create(token="current access token {}".format(i), expires=later)
            # make half of these Access Tokens have related Refresh Tokens, which prevent their deletion.
            if i % 2:
                RefreshtokenModel.objects.create(
                    token="old refresh token {}".format(i),
                    application=app,
                    access_token=old,
                    user=user,
                )
                RefreshtokenModel.objects.create(
                    token="current refresh token {}".format(i),
                    application=app,
                    access_token=new,
                    user=user,
                )
            GrantModel.objects.create(
                user=user,
                code="old grant code {}".format(i),
                application=app,
                expires=earlier,
                redirect_uri="https://localhost/redirect",
            )
            GrantModel.objects.create(
                user=user,
                code="new grant code {}".format(i),
                application=app,
                expires=later,
                redirect_uri="https://localhost/redirect",
            )

    def test_command_clear_tokens(self):
        self.assertEqual(AccesstokenModel.objects.count(), 200)
        self.assertEqual(RefreshtokenModel.objects.count(), 100)
        self.assertEqual(GrantModel.objects.count(), 200)
        call_command(
            "cleartokens",
        )
        self.assertEqual(AccesstokenModel.objects.count(), 150)
        self.assertEqual(RefreshtokenModel.objects.count(), 100)
        self.assertEqual(GrantModel.objects.count(), 100)
