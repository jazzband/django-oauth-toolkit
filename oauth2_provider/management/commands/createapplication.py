from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand

from oauth2_provider.models import get_application_model


Application = get_application_model()


class Command(BaseCommand):
    help = "Shortcut to create a new application in a programmatic way"

    def add_arguments(self, parser):
        parser.add_argument(
            "client_type",
            type=str,
            help="The client type, can be confidential or public",
        )
        parser.add_argument(
            "authorization_grant_type",
            type=str,
            help="The type of authorization grant to be used",
        )
        parser.add_argument(
            "--client-id",
            type=str,
            help="The ID of the new application",
        )
        parser.add_argument(
            "--user",
            type=str,
            help="The user the application belongs to",
        )
        parser.add_argument(
            "--redirect-uris",
            type=str,
            help="The redirect URIs, this must be a space separated string e.g 'URI1 URI2'",
        )
        parser.add_argument(
            "--client-secret",
            type=str,
            help="The secret for this application",
        )
        parser.add_argument(
            "--name",
            type=str,
            help="The name this application",
        )
        parser.add_argument(
            "--skip-authorization",
            action="store_true",
            help="The ID of the new application",
        )

    def handle(self, *args, **options):
        # Extract all fields related to the application, this will work now and in the future
        # and also with custom application models.
        application_fields = [field.name for field in Application._meta.fields]
        application_data = {}
        for key, value in options.items():
            # Data in options must be cleaned because there are unneded key-value like
            # verbosity and others. Also do not pass any None to the Application
            # instance so default values will be generated for those fields
            if key in application_fields and value:
                if key == "user":
                    application_data.update({"user_id": value})
                else:
                    application_data.update({key: value})

        new_application = Application(**application_data)

        try:
            new_application.full_clean()
        except ValidationError as exc:
            errors = "\n ".join(["- " + err_key + ": " + str(err_value) for err_key,
                                 err_value in exc.message_dict.items()])
            self.stdout.write(
                self.style.ERROR(
                    "Please correct the following errors:\n %s" % errors
                )
            )
        else:
            new_application.save()
            self.stdout.write(
                self.style.SUCCESS("New application created successfully")
            )
