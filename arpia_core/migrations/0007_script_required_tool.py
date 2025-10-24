from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("arpia_core", "0006_tool_alter_script_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="script",
            name="required_tool_slug",
            field=models.SlugField(blank=True, max_length=180),
        ),
    ]
