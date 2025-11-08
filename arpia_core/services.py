from typing import Iterable, Optional, Tuple
from django.db import transaction
from django.utils import timezone

from .models import Project, Asset, ObservedEndpoint

COMMON_PORTS = {22, 80, 443, 3306, 5432, 8080}


@transaction.atomic
def reconcile_endpoint(
    project: Project,
    ip: str,
    port: int,
    hostnames: Optional[Iterable[str]] = None,
    raw: Optional[dict] = None,
    source: str = "ingest",
) -> Tuple[Asset, ObservedEndpoint]:
    """
    Encontrar ou criar Asset e persistir ObservedEndpoint.
    Estratégia:
      - busca por ip em ips
      - busca por hostname(s) em hostnames
      - busca por identifier igual a ip/hostname
      - cria asset se não houver correspondência
    Retorna (asset, observed_endpoint).
    """
    hostnames = list(hostnames or [])
    raw = raw or {}

    candidate_assets = list(Asset.objects.filter(project=project).order_by("-last_seen"))
    asset = None
    for candidate in candidate_assets:
        ips = candidate.ips or []
        if ip in ips:
            asset = candidate
            break

    if not asset and hostnames:
        for h in hostnames:
            for candidate in candidate_assets:
                host_list = candidate.hostnames or []
                if h in host_list:
                    asset = candidate
                    break
            if asset:
                break

    if not asset:
        asset = Asset.objects.filter(project=project, identifier=ip).first()
    if not asset and hostnames:
        for h in hostnames:
            asset = Asset.objects.filter(project=project, identifier=h).first()
            if asset:
                break

    if not asset:
        identifier = hostnames[0] if hostnames else f"{ip}:{port}"
        asset = Asset.objects.create(
            project=project,
            identifier=identifier,
            name=identifier,
            hostnames=hostnames,
            ips=[ip],
            category="unknown",
            metadata={},
            last_seen=timezone.now(),
        )
    else:
        updated = False
        if ip not in asset.ips:
            asset.ips = asset.ips + [ip]
            updated = True
        for h in hostnames:
            if h and h not in asset.hostnames:
                asset.hostnames = asset.hostnames + [h]
                updated = True
        if updated:
            asset.last_seen = timezone.now()
            asset.save()

    endpoint = ObservedEndpoint.objects.create(
        asset=asset,
        ip=ip,
        port=port,
        proto=raw.get("protocol") or "tcp",
        service=raw.get("service", ""),
        path=raw.get("path", ""),
        raw=raw,
        source=source,
    )

    return asset, endpoint


def compute_contextual_score(asset: Asset, endpoint: ObservedEndpoint) -> float:
    """
    Pontuação simples [0,1] baseada em características do asset/endpoint.
    Implementação propositalmente simples para iniciar testes.
    """
    score = 0.1
    try:
        if (asset.metadata or {}).get("importance") == "high":
            score += 0.4
    except Exception:
        pass
    if endpoint.port in COMMON_PORTS:
        score += 0.25
    if endpoint.service:
        score += 0.15
    return min(1.0, round(score, 3))