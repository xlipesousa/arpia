from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import HuntFinding, HuntRecommendation
from .services.alerts import evaluate_alerts_for_finding


@receiver(post_save, sender=HuntFinding)
def trigger_alerts_on_finding(sender, instance: HuntFinding, **kwargs) -> None:
    evaluate_alerts_for_finding(instance)


@receiver(post_save, sender=HuntRecommendation)
def trigger_alerts_on_recommendation(sender, instance: HuntRecommendation, **kwargs) -> None:
    if instance.finding_id:
        evaluate_alerts_for_finding(instance.finding_id)
