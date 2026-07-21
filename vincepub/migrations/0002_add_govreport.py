# Generated manually - restores GovReport model that was previously deleted
# but is still referenced by vincepub forms and views.

from django.db import migrations, models
import bigvince.storage_backends
import vincepub.models


class Migration(migrations.Migration):

    dependencies = [
        ('vincepub', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='GovReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('contact_name', models.CharField(max_length=100)),
                ('contact_org', models.CharField(blank=True, max_length=100, null=True)),
                ('contact_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('contact_phone', models.CharField(blank=True, max_length=20, null=True)),
                ('reporter_pgp', models.TextField(blank=True, null=True)),
                ('credit_release', models.BooleanField(default=True)),
                ('affected_website', models.URLField(max_length=200)),
                ('vul_description', models.TextField()),
                ('tracking', models.CharField(blank=True, max_length=100, null=True)),
                ('vrf_id', models.CharField(blank=True, max_length=20, null=True)),
                ('comments', models.TextField(blank=True, null=True)),
                ('user_file', models.FileField(
                    blank=True,
                    null=True,
                    storage=bigvince.storage_backends.VRFReportsStorage(),
                    upload_to=vincepub.models.update_filename,
                )),
            ],
        ),
    ]
