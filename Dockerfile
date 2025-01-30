# syntax=docker/dockerfile:1.6.0
# this Dockerfile is located at the root so the build context
# includes oauth2_provider which is a requirement of the
# tests/app/idp. This way we build images with the source
# code from the repos for validation before publishing packages.

FROM python:3.11.6-slim

# allow embed sha1 at build time as release.
ARG GIT_SHA1

LABEL org.opencontainers.image.authors="https://jazzband.co/projects/django-oauth-toolkit"
LABEL org.opencontainers.image.source="https://github.com/jazzband/django-oauth-toolkit"
LABEL org.opencontainers.image.revision=${GIT_SHA1}

RUN pip install --upgrade pip setuptools uv

ENV SENTRY_RELEASE=${GIT_SHA1}
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV UV_CACHE_DIR /var/cache/uv
ENV UV_PROJECT_ENVIRONMENT /opt/dot/venv

RUN apt-get update
# Build Deps
RUN apt-get install -y --no-install-recommends libc-dev python3-dev file libev-dev
# bundle code in a virtual env to make copying to the final image without all the upstream stuff easier.
ENV PYTHONPATH="/code/tests/app/idp:$PYTHONPATH"
# need to update pip and setuptools for pep517 support required by gevent.


WORKDIR /code
COPY ./pyproject.toml /code
COPY ./uv.lock /code
COPY ./oauth2_provider /code/oauth2_provider

RUN uv sync --extra dev

COPY ./tests /code/tests

WORKDIR /code/tests/app/idp
