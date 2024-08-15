from django.conf import settings
from django.test import TestCase as DjangoTestCase
from django.test import TransactionTestCase as DjangoTransactionTestCase


# When there are multiple databases defined, Django tests will not work unless they are
# told which database(s) to work with. The multiple database scenario setup for these
# tests purposefully defines 'default' as an empty database in order to catch any
# assumptions in this package about database names and in particular to ensure there is
# no assumption that 'default' is a valid database.
# For any test that would usually use Django's TestCase or TransactionTestCase using
# the classes defined here is all that is required.
# In test code, anywhere the database is referenced the Django router needs to be used
# exactly like the package's code.
# For instance:
#     token_database = router.db_for_write(AccessToken)
#     with self.assertNumQueries(1, using=token_database):
# Without the 'using' option, this test fails in the multiple database scenario because
# 'default' is used.


def retrieve_current_databases():
    if len(settings.DATABASES) > 1:
        return [name for name in settings.DATABASES if name != "default"]
    else:
        return ["default"]


class OAuth2ProviderBase:
    @classmethod
    def setUpClass(cls):
        cls.databases = retrieve_current_databases()
        super().setUpClass()


class OAuth2ProviderTestCase(OAuth2ProviderBase, DjangoTestCase):
    """Place holder to allow overriding behaviors."""


class OAuth2ProviderTransactionTestCase(OAuth2ProviderBase, DjangoTransactionTestCase):
    """Place holder to allow overriding behaviors."""
