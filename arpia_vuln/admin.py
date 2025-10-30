from django.contrib import admin

from .models import VulnerabilityFinding, VulnScanSession, VulnTask


@admin.register(VulnScanSession)
class VulnScanSessionAdmin(admin.ModelAdmin):
	list_display = ("title", "project", "status", "owner", "created_at")
	list_filter = ("status", "project")
	search_fields = ("title", "reference", "project__name", "owner__username")
	ordering = ("-created_at",)
	readonly_fields = ("reference", "created_at", "updated_at")


@admin.register(VulnTask)
class VulnTaskAdmin(admin.ModelAdmin):
	list_display = ("name", "session", "kind", "status", "order")
	list_filter = ("kind", "status", "tool")
	search_fields = ("name", "session__title", "tool__name")
	ordering = ("session", "order")


@admin.register(VulnerabilityFinding)
class VulnerabilityFindingAdmin(admin.ModelAdmin):
	list_display = ("title", "session", "severity", "cvss_score", "cve", "host", "port")
	list_filter = ("severity", "status", "cve")
	search_fields = ("title", "cve", "host", "service", "session__title")
	ordering = ("-created_at",)
