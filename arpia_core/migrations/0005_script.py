from django.conf import settings
from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ("arpia_core", "0004_alter_projectmembership_id"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Script",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=180)),
                ("slug", models.SlugField(db_index=True, max_length=220)),
                ("description", models.TextField(blank=True)),
                ("filename", models.CharField(max_length=220)),
                ("content", models.TextField()),
                (
                    "kind",
                    models.CharField(
                        choices=[("default", "Default"), ("user", "Personalizado")],
                        default="user",
                        max_length=24,
                    ),
                ),
                ("tags", models.JSONField(blank=True, default=list)),
                ("source_path", models.CharField(blank=True, max_length=500)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=models.CASCADE,
                        related_name="scripts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
                "unique_together": {("owner", "slug"), ("owner", "filename")},
                "verbose_name": "Script",
                "verbose_name_plural": "Scripts",
            },
        ),
        migrations.AddConstraint(
            model_name="script",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=True),
                fields=("slug",),
                name="uniq_default_script_slug",
            ),
        ),
        migrations.AddConstraint(
            model_name="script",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=True),
                fields=("filename",),
                name="uniq_default_script_filename",
            ),
        ),
    ]
