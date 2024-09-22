import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from oauth2_provider.models import get_application_model
from oauth2_provider.views.application import ApplicationRegistration

from .common_testing import OAuth2ProviderTestCase as TestCase
from .models import SampleApplication


Application = get_application_model()
UserModel = get_user_model()


class BaseTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.foo_user = UserModel.objects.create_user("foo_user", "test@example.com", "123456")
        cls.bar_user = UserModel.objects.create_user("bar_user", "dev@example.com", "123456")


@pytest.mark.usefixtures("oauth2_settings")
class TestApplicationRegistrationView(BaseTest):
    @pytest.mark.oauth2_settings({"APPLICATION_MODEL": "tests.SampleApplication"})
    def test_get_form_class(self):
        """
        Tests that the form class returned by the "get_form_class" method is
        bound to custom application model defined in the
        "OAUTH2_PROVIDER_APPLICATION_MODEL" setting.
        """
        # Create a registration view and tests that the model form is bound
        # to the custom Application model
        application_form_class = ApplicationRegistration().get_form_class()
        self.assertEqual(SampleApplication, application_form_class._meta.model)

    def test_application_registration_user(self):
        self.client.login(username="foo_user", password="123456")

        get_response = self.client.get(reverse("oauth2_provider:register"))
        self.assertEqual(get_response.status_code, 200)

        self.assertNotIn("client_id", get_response.context["form"].fields)
        self.assertNotIn("client_secret", get_response.context["form"].fields)

        form_data = {
            "name": "Foo app",
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "redirect_uris": "http://example.com",
            "post_logout_redirect_uris": "http://other_example.com",
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "algorithm": "",
        }

        # Check that all fields in form_data are form fields
        for field in form_data.keys():
            self.assertIn(field, get_response.context["form"].fields.keys())

        response = self.client.post(reverse("oauth2_provider:register"), form_data)
        self.assertEqual(response.status_code, 302)

        app = get_application_model().objects.get(name="Foo app")
        self.assertEqual(app.user.username, "foo_user")
        app = Application.objects.get()
        self.assertEqual(app.name, form_data["name"])
        self.assertIsNotNone(app.client_id)
        self.assertIsNotNone(app.client_secret)
        self.assertEqual(app.redirect_uris, form_data["redirect_uris"])
        self.assertEqual(app.post_logout_redirect_uris, form_data["post_logout_redirect_uris"])
        self.assertEqual(app.client_type, form_data["client_type"])
        self.assertEqual(app.authorization_grant_type, form_data["authorization_grant_type"])
        self.assertEqual(app.algorithm, form_data["algorithm"])


class TestApplicationViews(BaseTest):
    @classmethod
    def _create_application(cls, name, user):
        return Application.objects.create(
            name=name,
            redirect_uris="http://example.com",
            post_logout_redirect_uris="http://other_example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=user,
        )

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.app_foo_1 = cls._create_application("app foo_user 1", cls.foo_user)
        cls.app_foo_2 = cls._create_application("app foo_user 2", cls.foo_user)
        cls.app_foo_3 = cls._create_application("app foo_user 3", cls.foo_user)

        cls.app_bar_1 = cls._create_application("app bar_user 1", cls.bar_user)
        cls.app_bar_2 = cls._create_application("app bar_user 2", cls.bar_user)

    def test_application_list(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["object_list"]), 3)

    def test_application_detail_owner(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:detail", args=(self.app_foo_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("client_secret", response.context)
        self.assertContains(response, self.app_foo_1.name)
        self.assertContains(response, self.app_foo_1.redirect_uris)
        self.assertContains(response, self.app_foo_1.post_logout_redirect_uris)
        self.assertContains(response, self.app_foo_1.client_type)
        self.assertContains(response, self.app_foo_1.authorization_grant_type)

        # We don't allow users to update this, setting it False to test context
        self.app_foo_1.hash_client_secret = False
        self.app_foo_1.save()

        response = self.client.get(reverse("oauth2_provider:detail", args=(self.app_foo_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertIn("client_secret", response.context)

    def test_application_detail_not_owner(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:detail", args=(self.app_bar_1.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_application_update(self):
        self.client.login(username="foo_user", password="123456")

        get_response = self.client.get(reverse("oauth2_provider:update", args=(self.app_foo_1.pk,)))
        self.assertEqual(get_response.status_code, 200)

        self.assertNotIn("client_id", get_response.context["form"].fields)
        self.assertNotIn("client_secret", get_response.context)
        self.assertNotIn("client_secret", get_response.context["form"].fields)
        self.assertNotIn("hash_client_secret", get_response.context["form"].fields)

        new_app_name = self.app_foo_1.name + " - Updated"

        form_data = {
            "name": new_app_name,
            "redirect_uris": "http://new_example.com",
            "post_logout_redirect_uris": "http://new_other_example.com",
            "client_type": Application.CLIENT_PUBLIC,
            "authorization_grant_type": Application.GRANT_OPENID_HYBRID,
        }

        # Check that all fields in form_data are form fields
        for field in form_data.keys():
            self.assertIn(field, get_response.context["form"].fields.keys())

        response = self.client.post(
            reverse("oauth2_provider:update", args=(self.app_foo_1.pk,)),
            data=form_data,
        )
        self.assertRedirects(response, reverse("oauth2_provider:detail", args=(self.app_foo_1.pk,)))

        self.app_foo_1.refresh_from_db()
        self.assertEqual(self.app_foo_1.name, new_app_name)
        self.assertEqual(self.app_foo_1.redirect_uris, form_data["redirect_uris"])
        self.assertEqual(self.app_foo_1.post_logout_redirect_uris, form_data["post_logout_redirect_uris"])
        self.assertEqual(self.app_foo_1.client_type, form_data["client_type"])
        self.assertEqual(self.app_foo_1.authorization_grant_type, form_data["authorization_grant_type"])
