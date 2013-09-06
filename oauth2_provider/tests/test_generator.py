from __future__ import unicode_literals

from django.test import TestCase

from ..settings import oauth2_settings
from ..generators import (BaseHashGenerator, ClientIdGenerator, ClientSecretGenerator,
                          generate_client_id, generate_client_secret)


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
