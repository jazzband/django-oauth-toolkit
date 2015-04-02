# -*- coding: utf-8 -*-
import datetime
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
        # Adding index on 'RefreshToken', fields ['token']
        db.create_index(u'oauth2_provider_refreshtoken', ['token'])

        # Adding index on 'Grant', fields ['code']
        db.create_index(u'oauth2_provider_grant', ['code'])

        # Adding index on 'AccessToken', fields ['token']
        db.create_index(u'oauth2_provider_accesstoken', ['token'])


    def backwards(self, orm):
        # Removing index on 'AccessToken', fields ['token']
        db.delete_index(u'oauth2_provider_accesstoken', ['token'])

        # Removing index on 'Grant', fields ['code']
        db.delete_index(u'oauth2_provider_grant', ['code'])

        # Removing index on 'RefreshToken', fields ['token']
        db.delete_index(u'oauth2_provider_refreshtoken', ['token'])


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
        u"%s.%s" % (User._meta.app_label, User._meta.object_name): {
            'Meta': {'object_name': User.__name__},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
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
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (User._meta.app_label, User._meta.object_name)})
        },
        u"%s.%s" % (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name): {
            'Meta': {'object_name': ApplicationModel.__name__},
            'authorization_grant_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'client_id': ('django.db.models.fields.CharField', [], {'default': "'30f17d266183cd455bc57ce8548a439db3491353'", 'unique': 'True', 'max_length': '100'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': "'18e68df61ad8e1af355644ddf6a636b269b6309aafbd2a34d4f5ed6c5562e44c0792c5b2441571e85cbf8a85249dca5537dedb6fd6f60e134f4a60f3865c8395'", 'max_length': '255', 'blank': 'True'}),
            'client_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uris': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (User._meta.app_label, User._meta.object_name)})
        },
        u'oauth2_provider.grant': {
            'Meta': {'object_name': 'Grant'},
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name)}),
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (User._meta.app_label, User._meta.object_name)})
        },
        u'oauth2_provider.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'refresh_token'", 'unique': 'True', 'to': u"orm['oauth2_provider.AccessToken']"}),
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (ApplicationModel._meta.app_label, ApplicationModel._meta.object_name)}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (User._meta.app_label, User._meta.object_name)})
        }
    }

    complete_apps = ['oauth2_provider']
