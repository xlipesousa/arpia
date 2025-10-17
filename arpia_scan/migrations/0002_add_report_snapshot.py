from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("arpia_scan", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scansession",
            name="report_snapshot",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
