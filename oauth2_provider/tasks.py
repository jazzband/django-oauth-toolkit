from celery import shared_task


@shared_task
def clear_tokens():
    from oauth2_provider.models import clear_expired

    clear_expired()
