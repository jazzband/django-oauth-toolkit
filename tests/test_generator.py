from django.test import TestCase

from oauth2_provider.generators import (
    BaseHashGenerator, ClientIdGenerator, ClientSecretGenerator,
    generate_client_id, generate_client_secret
)
from oauth2_provider.settings import oauth2_settings


class MockHashGenerator(BaseHashGenerator):
    def hash(self):
        return 42


class TestGenerators(TestCase):
    def tearDown(self):
        oauth2_settings.CLIENT_ID_GENERATOR_CLASS = ClientIdGenerator
        oauth2_settings.CLIENT_SECRET_GENERATOR_CLASS = ClientSecretGenerator

    def test_generate_client_id(self):
        g = oauth2_settings.CLIENT_ID_GENERATOR_CLASS()
        self.assertEqual(len(g.hash()), 40)

        oauth2_settings.CLIENT_ID_GENERATOR_CLASS = MockHashGenerator
        self.assertEqual(generate_client_id(), 42)

    def test_generate_secret_id(self):
        g = oauth2_settings.CLIENT_SECRET_GENERATOR_CLASS()
        self.assertEqual(len(g.hash()), 128)

        oauth2_settings.CLIENT_SECRET_GENERATOR_CLASS = MockHashGenerator
        self.assertEqual(generate_client_secret(), 42)

    def test_basegen_misuse(self):
        g = BaseHashGenerator()
        self.assertRaises(NotImplementedError, g.hash)
