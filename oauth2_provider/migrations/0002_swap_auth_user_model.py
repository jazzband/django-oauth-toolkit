# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models
from django.conf import settings


class Migration(SchemaMigration):

    def forwards(self, orm):
        if settings.AUTH_USER_MODEL == settings.OAUTH2_USER_MODEL:
            return
        # Changing field 'Application.user'
        db.alter_column(u'oauth2_provider_application', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.OAUTH2_USER_MODEL]))

        # Changing field 'RefreshToken.user'
        db.alter_column(u'oauth2_provider_refreshtoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.OAUTH2_USER_MODEL]))

        # Changing field 'Grant.user'
        db.alter_column(u'oauth2_provider_grant', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.OAUTH2_USER_MODEL]))

        # Changing field 'AccessToken.user'
        db.alter_column(u'oauth2_provider_accesstoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.OAUTH2_USER_MODEL]))

    def backwards(self, orm):
        # Changing field 'Application.user'
        db.alter_column(u'oauth2_provider_application', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.AUTH_USER_MODEL]))

        # Changing field 'RefreshToken.user'
        db.alter_column(u'oauth2_provider_refreshtoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.AUTH_USER_MODEL]))

        # Changing field 'Grant.user'
        db.alter_column(u'oauth2_provider_grant', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.AUTH_USER_MODEL]))

        # Changing field 'AccessToken.user'
        db.alter_column(u'oauth2_provider_accesstoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[settings.AUTH_USER_MODEL]))


    models = {
        settings.OAUTH2_USER_MODEL.lower(): {
            'Meta': {'object_name': settings.OAUTH2_USER_MODEL.split('.')[-1]},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
        },
        u'oauth2_provider.accesstoken': {
            'Meta': {'object_name': 'AccessToken'},
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['oauth2_provider.Application']"}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % settings.OAUTH2_USER_MODEL})
        },
        u'oauth2_provider.application': {
            'Meta': {'object_name': 'Application'},
            'authorization_grant_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'client_id': ('django.db.models.fields.CharField', [], {'default': "u'VA1<=e#rvf+<7z O;S(!FOT\\\\PwQu(Y9%E+@_>N7h'", 'unique': 'True', 'max_length': '100'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': 'u\'EJ$+l3_Z2Yn=!UExr5V*>^ye\\\\0<iZ;:douT-ppHZp<`Xo="OL_($gE5eub8K=R/=]WAIH,ad}z_iMfS)?YVJ3zVy]G$5%Mv7_{pN5Df9H3atddZmhQ+RLF LOrY/8Jjs\'', 'max_length': '255', 'blank': 'True'}),
            'client_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uris': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % settings.OAUTH2_USER_MODEL})
        },
        u'oauth2_provider.grant': {
            'Meta': {'object_name': 'Grant'},
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['oauth2_provider.Application']"}),
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % settings.OAUTH2_USER_MODEL})
        },
        u'oauth2_provider.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'refresh_token'", 'unique': 'True', 'to': u"orm['oauth2_provider.AccessToken']"}),
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['oauth2_provider.Application']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % settings.OAUTH2_USER_MODEL})
        },
    }

    if settings.AUTH_USER_MODEL != settings.OAUTH2_USER_MODEL:
        models[settings.AUTH_USER_MODEL.lower()] = {
            'Meta': {'object_name': settings.AUTH_USER_MODEL.split('.')[-1]},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
        }

    complete_apps = ['oauth2_provider']
