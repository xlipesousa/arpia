from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ("arpia_hunt", "0005_attacktactic_attacktechnique_huntrecommendation_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="huntrecommendation",
            name="confidence_note",
            field=models.CharField(blank=True, max_length=512),
        ),
        migrations.AddField(
            model_name="huntrecommendation",
            name="playbook_slug",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddIndex(
            model_name="huntrecommendation",
            index=models.Index(
                fields=["recommendation_type", "created_at"],
                name="idx_hunt_rec_auto_recent",
                condition=Q(generated_by="automation"),
            ),
        ),
        migrations.AddIndex(
            model_name="huntrecommendation",
            index=models.Index(
                fields=["playbook_slug"],
                name="idx_hunt_rec_playbook",
                condition=Q(playbook_slug__gt=""),
            ),
        ),
    ]
