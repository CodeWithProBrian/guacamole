# Generated by Django 5.1.7 on 2025-04-03 01:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Inno', '0018_customuser_profile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='profile',
            field=models.ImageField(blank=True, upload_to='profile'),
        ),
    ]
