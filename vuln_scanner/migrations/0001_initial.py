# Generated by Django 2.1 on 2020-07-22 18:23

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='site',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('site_url', models.URLField()),
                ('output', models.TextField()),
                ('date_posted', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
    ]
