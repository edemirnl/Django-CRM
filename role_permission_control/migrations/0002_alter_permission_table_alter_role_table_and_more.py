# Generated by Django 4.2.1 on 2025-06-10 12:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('role_permission_control', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='permission',
            table='permission',
        ),
        migrations.AlterModelTable(
            name='role',
            table='role',
        ),
        migrations.AlterModelTable(
            name='rolepermission',
            table='role_permission',
        ),
    ]
