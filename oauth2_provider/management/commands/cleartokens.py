from dateutil.parser import parse
from django.core.management.base import BaseCommand

from ...models import clear_expired


class Command(BaseCommand):
    """Clear expired tokens, add custom date to limit clear tokens before this date."""
    help = "Can be run as a cronjob or directly to clean out expired tokens"
    
    def add_arguments(self, parser):
        parser.add_argument('--before')

    def handle(self, *args, **options):
        before = None
        try:
            before = options.get('before')
            try:
                before = parse(before)
            except Exception:
                print('Not valid datetime')
                return
        clear_expired(before)
