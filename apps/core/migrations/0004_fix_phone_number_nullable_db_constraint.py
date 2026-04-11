from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_add_user_type_and_advocate_fields'),
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE core_userprofile ALTER COLUMN phone_number DROP NOT NULL;",
            reverse_sql="ALTER TABLE core_userprofile ALTER COLUMN phone_number SET NOT NULL;",
        ),
    ]
