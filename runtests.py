#!/usr/bin/env python
import os
import sys
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--coverage", dest="coverage", action='store_true')

    args = parser.parse_args()
    if args.coverage:
        test_cmd = "test_coverage"
    else:
        test_cmd = "test"

    app_to_test = "oauth2_provider"

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "oauth2_provider.tests.settings")

    from django.core.management import execute_from_command_line
    execute_from_command_line([sys.argv[0], test_cmd, app_to_test])
