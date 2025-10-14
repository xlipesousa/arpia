from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db import migrations, models
from django.utils.text import slugify


def assign_owner(apps, schema_editor):
    Project = apps.get_model("arpia_core", "Project")
    Membership = apps.get_model("arpia_core", "ProjectMembership")
    user_app, user_model = settings.AUTH_USER_MODEL.split(".")
    User = apps.get_model(user_app, user_model)

    owner = User.objects.order_by("id").first()
    if owner is None:
        owner = User(username="system", email="system@arpia.local", is_active=False)
        if hasattr(owner, "set_unusable_password"):
            owner.set_unusable_password()
        else:
            owner.password = make_password(None)
        owner.save()

    for project in Project.objects.all():
        if not project.slug:
            project.slug = slugify(project.name) or slugify(str(project.pk))
        if getattr(project, "owner_id", None) is None:
            project.owner = owner
        project.save(update_fields=["owner", "slug"])
        Membership.objects.get_or_create(
            project=project,
            user=project.owner,
            defaults={"role": "owner", "invited_by": owner},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("arpia_core", "0002_alter_asset_id_alter_observedendpoint_id_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RenameField(
            model_name="project",
            old_name="summary",
            new_name="description",
        ),
        migrations.RenameField(
            model_name="project",
            old_name="title",
            new_name="name",
        ),
        migrations.AlterField(
            model_name="project",
            name="name",
            field=models.CharField(max_length=220),
        ),
        migrations.AlterField(
            model_name="project",
            name="slug",
            field=models.SlugField(max_length=220),
        ),
        migrations.AddField(
            model_name="project",
            name="client_name",
            field=models.CharField(blank=True, max_length=220),
        ),
        migrations.AddField(
            model_name="project",
            name="credentials_json",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="project",
            name="end_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="project",
            name="hosts",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="project",
            name="metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="project",
            name="networks",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="project",
            name="owner",
            field=models.ForeignKey(null=True, on_delete=models.CASCADE, related_name="projects_owned", to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name="project",
            name="ports",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="project",
            name="protected_hosts",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="project",
            name="start_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="project",
            name="status",
            field=models.CharField(choices=[("draft", "Rascunho"), ("active", "Ativo"), ("paused", "Pausado"), ("completed", "Concluído"), ("archived", "Arquivado")], default="draft", max_length=24),
        ),
        migrations.AddField(
            model_name="project",
            name="timezone",
            field=models.CharField(blank=True, default="America/Sao_Paulo", max_length=64),
        ),
        migrations.AddField(
            model_name="project",
            name="visibility",
            field=models.CharField(default="private", max_length=24),
        ),
        migrations.CreateModel(
            name="ProjectMembership",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role", models.CharField(choices=[("owner", "Owner"), ("editor", "Editor"), ("viewer", "Viewer")], default="viewer", max_length=24)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("invited_by", models.ForeignKey(blank=True, null=True, on_delete=models.SET_NULL, related_name="project_invitations_sent", to=settings.AUTH_USER_MODEL)),
                ("project", models.ForeignKey(on_delete=models.CASCADE, related_name="memberships", to="arpia_core.project")),
                ("user", models.ForeignKey(on_delete=models.CASCADE, related_name="project_memberships", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "Participante de Projeto",
                "verbose_name_plural": "Participantes de Projeto",
                "unique_together": {("project", "user")},
            },
        ),
        migrations.AddConstraint(
            model_name="project",
            constraint=models.UniqueConstraint(fields=("owner", "slug"), name="uniq_project_owner_slug"),
        ),
        migrations.RunPython(assign_owner, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="project",
            name="owner",
            field=models.ForeignKey(on_delete=models.CASCADE, related_name="projects_owned", to=settings.AUTH_USER_MODEL),
        ),
    ]
