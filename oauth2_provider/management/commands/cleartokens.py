from django.core.management.base import BaseCommand

from ...models import clear_expired


class Command(BaseCommand):
    help = "Can be run as a cronjob or directly to clean out expired tokens"
    
    def add_arguments(self, parser):
        parser.add_argument('before')

        
    def handle(self, *args, **options):
        before = options.get('before')
        import pdb; pdb.set_trace()
        clear_expired(before)
