# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2016-08-30 01:04
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_auto_20160822_2103'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certificate',
            name='common_name',
            field=models.TextField(editable=False, null=True),
        ),
    ]
