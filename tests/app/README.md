# Test Apps

These apps are for local end to end testing of DOT features. They were implemented to save maintainers the trouble of setting up
local test environments.

## /tests/app/idp

This is an example IDP implementation for end to end testing. There are pre-configured fixtures which will work with the sample RP.

username: superuser
password: password

### Development Tasks

* starting up the idp

  ```bash
  cd tests/app/idp
  # create a virtual env if that is something you do
  python manage.py migrate
  python manage.py loaddata fixtures/seed.json
  python manage.py runserver
  # open http://localhost:8000/admin

  ```

* update fixtures

  You can update data in the IDP and then dump the data to a new seed file as follows.

  ```
  python -Xutf8 ./manage.py dumpdata -e sessions  -e admin.logentry -e auth.permission -e contenttypes.contenttype --natural-foreign --natural-primary --indent 2 > fixtures/seed.json
  ```

## /test/app/rp

This is an example RP. It is a SPA built with Svelte.

### Development Tasks

* starting the RP

  ```bash
  cd test/apps/rp
  npm install
  npm run dev
  # open http://localhost:5173
  ```