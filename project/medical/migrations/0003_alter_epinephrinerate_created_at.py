# Generated by Django 4.1 on 2022-08-15 07:08

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('medical', '0002_alter_epinephrinerate_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='epinephrinerate',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2022, 8, 15, 16, 8, 6, 904647)),
        ),
    ]
