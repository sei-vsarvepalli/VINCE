# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vince', '0003_auto_20230418_1538'),
    ]

    operations = [
        migrations.AlterField(
            model_name='caserequest',
            name='submission_type',
            field=models.CharField(
                choices=[('email', 'email'), ('web', 'web'), ('api', 'api'), ('manual', 'manual')],
                default='web',
                max_length=15,
            ),
        ),
    ]
