# Generated manually for troublesome user flag feature

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vinny', '0002_auto_20220719_1530'),
    ]

    operations = [
        migrations.AddField(
            model_name='vinceprofile',
            name='troublesome',
            field=models.BooleanField(default=False, help_text='Flag indicating this user requires special attention from coordinators'),
        ),
    ]
