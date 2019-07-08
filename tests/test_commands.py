from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from oauth2_provider.models import get_application_model

Application = get_application_model()


class CreateApplicationTest(TestCase):

    def test_command_creates_application(self):
        output = StringIO()
        self.assertEqual(Application.objects.count(), 0)
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            stdout=output,
        )
        self.assertEqual(Application.objects.count(), 1)
        self.assertIn('New application created successfully', output.getvalue())

    def test_missing_required_args(self):
        self.assertEqual(Application.objects.count(), 0)
        with self.assertRaises(CommandError) as ctx:
            call_command(
                'createapplication',
                '--redirect-uris=http://example.com http://example2.com',
            )

        self.assertIn('client_type', ctx.exception.args[0])
        self.assertIn('authorization_grant_type', ctx.exception.args[0])
        self.assertEqual(Application.objects.count(), 0)

    def test_command_creates_application_with_skipped_auth(self):
        self.assertEqual(Application.objects.count(), 0)
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            '--skip-authorization',
        )
        app = Application.objects.get()

        self.assertTrue(app.skip_authorization)

    def test_application_created_normally_with_no_skipped_auth(self):
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
        )
        app = Application.objects.get()

        self.assertFalse(app.skip_authorization)

    def test_application_created_with_name(self):
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            '--name=TEST',
        )
        app = Application.objects.get()

        self.assertEqual(app.name, 'TEST')

    def test_application_created_with_client_secret(self):
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            '--client-secret=SECRET',
        )
        app = Application.objects.get()

        self.assertEqual(app.client_secret, 'SECRET')

    def test_application_created_with_client_id(self):
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            '--client-id=someId',
        )
        app = Application.objects.get()

        self.assertEqual(app.client_id, 'someId')

    def test_application_created_with_user(self):
        User = get_user_model()
        user = User.objects.create()
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            '--user=%s' % user.pk,
        )
        app = Application.objects.get()

        self.assertEqual(app.user, user)

    def test_validation_failed_message(self):
        output = StringIO()
        call_command(
            'createapplication',
            'confidential',
            'authorization-code',
            '--redirect-uris=http://example.com http://example2.com',
            '--user=783',
            stdout=output,
        )

        self.assertIn('user', output.getvalue())
        self.assertIn('783', output.getvalue())
        self.assertIn('does not exist', output.getvalue())
