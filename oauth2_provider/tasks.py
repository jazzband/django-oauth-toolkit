from celery import shared_task


@shared_task
def clear_tokens():
    from ...models import clear_expired  # noqa

    clear_expired()
