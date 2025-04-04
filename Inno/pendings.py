from django.core.management.base import BaseCommand
from django.utils import timezone
from Inno.models import PendingUser

class Command(BaseCommand):
    help = 'Cleans up expired pending user registrations'

    def handle(self, *args, **options):
        expired_users = PendingUser.objects.filter(expires_at__lt=timezone.now())
        count = expired_users.count()
        expired_users.delete()
        self.stdout.write(f'Deleted {count} expired pending users')