# Generated by Django 2.1 on 2020-07-30 07:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='output',
        ),
        migrations.RemoveField(
            model_name='profile',
            name='site_url',
        ),
    ]
