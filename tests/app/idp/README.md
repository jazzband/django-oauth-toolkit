# TEST IDP

This is an example IDP implementation for end to end testing.

username: superuser
password: password

## Development Tasks

* update fixtures

  ```
  python -Xutf8 ./manage.py dumpdata -e sessions  -e admin.logentry -e auth.permission -e contenttypes.contenttype -e oauth2_provider.grant -e oauth2_provider.accesstoken -e oauth2_provider.refreshtoken -e oauth2_provider.idtoken --natural-foreign --natural-primary --indent 2 > fixtures/seed.json
  ```

  *check seeds as you produce them to makre sure any unrequired models are excluded to keep our seeds as small as possible.*
