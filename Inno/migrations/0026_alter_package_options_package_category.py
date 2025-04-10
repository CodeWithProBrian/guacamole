# Generated by Django 5.1.7 on 2025-04-05 14:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Inno', '0025_userprofile_bio_userprofile_date_of_birth_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='package',
            options={'ordering': ['category', 'id']},
        ),
        migrations.AddField(
            model_name='package',
            name='category',
            field=models.CharField(choices=[('DATA', 'Data'), ('SMS', 'SMS'), ('MINUTES', 'Minutes')], default='DATA', max_length=10),
        ),
    ]
