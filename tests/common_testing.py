from django.conf import settings
from django.test import TestCase as DjangoTestCase
from django.test import TransactionTestCase as DjangoTransactionTestCase


class OAuth2ProviderTestCase(DjangoTestCase):
    """Place holder to allow overriding behaviors."""


class OAuth2ProviderTransactionTestCase(DjangoTransactionTestCase):
    """Place holder to allow overriding behaviors."""


if len(settings.DATABASES) > 1:
    # There are multiple databases defined. When this happens Django tests will not
    # work unless they are told which database(s) to work with. The multiple
    # database scenario setup for these tests purposefully defines 'default' as an
    # empty database in order to catch any assumptions in this package about database
    # names and in particular to ensure there is no assumption that 'default' is a
    # valid database.
    # For any test that would usually use Django's TestCase or TransactionTestCase
    # using the classes defined here is all that is required.
    # Any test that uses pytest's django_db need to base in a databases parameter
    # using this definition of test_database_names.
    # In test code, anywhere the default database is used the variable
    # database_for_oauth2_provider must be used in its place. For instance,
    #     with self.assertNumQueries(1, using=database_for_oauth2_provider):
    # without the using option this fails because default is used.
    test_database_names = {name for name in settings.DATABASES if name != "default"}
    database_for_oauth2_provider = "alpha"
    OAuth2ProviderTestCase.databases = test_database_names
    OAuth2ProviderTransactionTestCase.databases = test_database_names
else:
    test_database_names = {"default"}
    database_for_oauth2_provider = "default"
