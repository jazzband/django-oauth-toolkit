# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

from ..compat import get_user_model
from ..models import get_application_model


User = get_user_model()
App = get_application_model()


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'ApplicationInstallation'
        db.create_table(u'oauth2_provider_applicationinstallation', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('application', self.gf('django.db.models.fields.related.ForeignKey')(to=orm["%s.%s" % (App._meta.app_label, App._meta.object_name)])),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm["%s.%s" % (User._meta.app_label, User._meta.object_name)])),
            ('grant', self.gf('django.db.models.fields.related.OneToOneField')(related_name=u'application_installation', unique=True, null=True, on_delete=models.SET_NULL, to=orm['oauth2_provider.Grant'])),
            ('access_token', self.gf('django.db.models.fields.related.OneToOneField')(related_name=u'application_installation', unique=True, null=True, on_delete=models.SET_NULL, to=orm['oauth2_provider.AccessToken'])),
            ('refresh_token', self.gf('django.db.models.fields.related.OneToOneField')(related_name=u'application_installation', unique=True, null=True, on_delete=models.SET_NULL, to=orm['oauth2_provider.RefreshToken'])),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now)),
        ))
        db.send_create_signal(u'oauth2_provider', ['ApplicationInstallation'])

        # Deleting field 'Application.user'
        db.delete_column(u'oauth2_provider_application', 'user_id')

        # Deleting field 'RefreshToken.application'
        db.delete_column(u'oauth2_provider_refreshtoken', 'application_id')

        # Deleting field 'RefreshToken.user'
        db.delete_column(u'oauth2_provider_refreshtoken', 'user_id')

        # Deleting field 'Grant.application'
        db.delete_column(u'oauth2_provider_grant', 'application_id')

        # Deleting field 'Grant.user'
        db.delete_column(u'oauth2_provider_grant', 'user_id')

        # Deleting field 'AccessToken.application'
        db.delete_column(u'oauth2_provider_accesstoken', 'application_id')

        # Deleting field 'AccessToken.user'
        db.delete_column(u'oauth2_provider_accesstoken', 'user_id')


    def backwards(self, orm):
        # Deleting model 'ApplicationInstallation'
        db.delete_table(u'oauth2_provider_applicationinstallation')


        # User chose to not deal with backwards NULL issues for 'Application.user'
        raise RuntimeError("Cannot reverse this migration. 'Application.user' and its values cannot be restored.")

        # User chose to not deal with backwards NULL issues for 'RefreshToken.application'
        raise RuntimeError("Cannot reverse this migration. 'RefreshToken.application' and its values cannot be restored.")

        # User chose to not deal with backwards NULL issues for 'RefreshToken.user'
        raise RuntimeError("Cannot reverse this migration. 'RefreshToken.user' and its values cannot be restored.")

        # User chose to not deal with backwards NULL issues for 'Grant.application'
        raise RuntimeError("Cannot reverse this migration. 'Grant.application' and its values cannot be restored.")

        # User chose to not deal with backwards NULL issues for 'Grant.user'
        raise RuntimeError("Cannot reverse this migration. 'Grant.user' and its values cannot be restored.")

        # User chose to not deal with backwards NULL issues for 'AccessToken.application'
        raise RuntimeError("Cannot reverse this migration. 'AccessToken.application' and its values cannot be restored.")

        # User chose to not deal with backwards NULL issues for 'AccessToken.user'
        raise RuntimeError("Cannot reverse this migration. 'AccessToken.user' and its values cannot be restored.")

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
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        u"%s.%s" % (App._meta.app_label, App._meta.object_name): {
            'Meta': {'object_name': App.__name__},
            'authorization_grant_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'client_id': ('django.db.models.fields.CharField', [], {'default': 'u\')4qiQa)d1%uQHPmc"%!0*_-+G|I"hhqqzl#%LN1e\'', 'unique': 'True', 'max_length': '100'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': 'u\'(gJrAq|mq}Bc,3<@Ir^]1H!t^|Q,wBQ;Qj]dKX\\\'ibS}_s-\\\\(W,-_B"\\\\\\\\-pFjF#i.{z{]vES7&@<[@G)HXC[L\\\\<#\\\\6[67\\\\9K-9"T=>[@{QXtz\\\'zu(*g3N|"2iRrbM`d{.\'', 'max_length': '255', 'blank': 'True'}),
            'client_type': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uris': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        u'oauth2_provider.applicationinstallation': {
            'Meta': {'object_name': 'ApplicationInstallation'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'application_installation'", 'unique': 'True', 'null': 'True', 'on_delete': 'models.SET_NULL', 'to': u"orm['oauth2_provider.AccessToken']"}),
            'application': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (App._meta.app_label, App._meta.object_name)}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'grant': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'application_installation'", 'unique': 'True', 'null': 'True', 'on_delete': 'models.SET_NULL', 'to': u"orm['oauth2_provider.Grant']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'refresh_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'application_installation'", 'unique': 'True', 'null': 'True', 'on_delete': 'models.SET_NULL', 'to': u"orm['oauth2_provider.RefreshToken']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s.%s']"% (User._meta.app_label, User._meta.object_name)})
        },
        u'oauth2_provider.grant': {
            'Meta': {'object_name': 'Grant'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'scope': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        u'oauth2_provider.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'refresh_token'", 'unique': 'True', 'to': u"orm['oauth2_provider.AccessToken']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        }
    }

    complete_apps = ['oauth2_provider']