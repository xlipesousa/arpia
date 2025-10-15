from django.conf import settings
from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ("arpia_core", "0005_script"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Tool",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=120)),
                ("slug", models.SlugField(max_length=150)),
                ("description", models.TextField(blank=True)),
                ("path", models.CharField(max_length=500)),
                ("category", models.CharField(blank=True, max_length=80)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=models.CASCADE,
                        related_name="tools",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Ferramenta",
                "verbose_name_plural": "Ferramentas",
                "ordering": ("name",),
            },
        ),
        migrations.CreateModel(
            name="Wordlist",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=150)),
                ("slug", models.SlugField(max_length=180)),
                ("description", models.TextField(blank=True)),
                ("path", models.CharField(max_length=500)),
                ("category", models.CharField(blank=True, max_length=80)),
                ("tags", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=models.CASCADE,
                        related_name="wordlists",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Wordlist",
                "verbose_name_plural": "Wordlists",
                "ordering": ("name",),
            },
        ),
        migrations.AddConstraint(
            model_name="tool",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=False),
                fields=("owner", "name"),
                name="uniq_tool_owner_name",
            ),
        ),
        migrations.AddConstraint(
            model_name="tool",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=False),
                fields=("owner", "slug"),
                name="uniq_tool_owner_slug",
            ),
        ),
        migrations.AddConstraint(
            model_name="wordlist",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=False),
                fields=("owner", "name"),
                name="uniq_wordlist_owner_name",
            ),
        ),
        migrations.AddConstraint(
            model_name="wordlist",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=False),
                fields=("owner", "slug"),
                name="uniq_wordlist_owner_slug",
            ),
        ),
        migrations.AlterField(
            model_name="script",
            name="id",
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
    ]
