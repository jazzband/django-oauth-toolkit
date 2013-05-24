#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "example.settings")
    example_project_dir = os.path.join(os.path.dirname(__file__), 'example')
    sys.path.insert(0, example_project_dir)
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
