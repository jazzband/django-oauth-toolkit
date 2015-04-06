# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


try:
    from django.contrib.auth import get_user_model
except ImportError:  # django < 1.5
    from django.contrib.auth.models import User
else:
    User = get_user_model()

from oauth2_provider.models import get_application_model
ApplicationModel = get_application_model()


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding field 'Application.skip_authorization'
        db.add_column(u'oauth2_provider_application', 'skip_authorization',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)


        # Changing field 'AccessToken.user'
        db.alter_column(u'oauth2_provider_accesstoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['%s.%s' % (User._meta.app_label, User._meta.object_name)], null=True))

    def backwards(self, orm):
        # Deleting field 'Application.skip_authorization'
        db.delete_column(u'oauth2_provider_application', 'skip_authorization')


        # User chose to not deal with backwards NULL issues for 'AccessToken.user'
        raise RuntimeError("Cannot reverse this migration. 'AccessToken.user' and its values cannot be restored.")

        # The following code is provided here to aid in writing a correct migration
        # Changing field 'AccessToken.user'
        db.alter_column(u'oauth2_provider_accesstoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['%s.%s' % (User._meta.app_label, User._meta.object_name)]))

    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'%s.%s' % (User._meta.app_label, User._meta.object_name): {
            'Meta': {'object_name': User.__name__},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Group']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Permission']"}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'oauth2_provider.accesstoken': {
            'Meta': {'object_name': 'AccessToken'},
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name)}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255', 'db_index': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']" % (User._meta.app_label, User._meta.object_name), 'null': 'True', 'blank': 'True'})
        },
        u"%s.%s" % (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name): {
            'Meta': {'object_name': ApplicationModel.__name__},
            'authorization_grant_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'client_id': ('django.db.models.fields.CharField', [], {'default': "u'amXbsy974anVL3xgzY2dczL8SRMSXA5awkXyjtsY'", 'unique': 'True', 'max_length': '100', 'db_index': 'True'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': "u'trXjdJB8EO7HPsZcPswIT1l0Zdg3W3AWDxXvh5Jj9rON2MAoRT6YVDSHqKFB76rIgD9X9YBxoY7jjT4Mj12UHc2BjCCXJI4nzx4qwEwoyZ7l6N88xiHaM6J5qXeWJ6e3'", 'max_length': '255', 'db_index': 'True', 'blank': 'True'}),
            'client_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uris': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'skip_authorization': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']" % (User._meta.app_label, User._meta.object_name)})
        },
        u'oauth2_provider.grant': {
            'Meta': {'object_name': 'Grant'},
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['%s.%s']"% (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name)}),
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255', 'db_index': 'True'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']" % (User._meta.app_label, User._meta.object_name)})
        },
        u'oauth2_provider.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'refresh_token'", 'unique': 'True', 'to': u"orm['oauth2_provider.AccessToken']"}),
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name)}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255', 'db_index': 'True'}),
        'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']" % (User._meta.app_label, User._meta.object_name)})
    }
}

complete_apps = ['oauth2_provider']
