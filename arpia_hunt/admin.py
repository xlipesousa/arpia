from django.contrib import admin

from . import models


@admin.register(models.HuntFinding)
class HuntFindingAdmin(admin.ModelAdmin):
	list_display = (
		"vulnerability",
		"project",
		"cve",
		"severity",
		"host",
		"port",
		"last_synced_at",
	)
	list_filter = ("project", "severity", "is_active")
	search_fields = ("vulnerability__title", "cve", "host", "service")
	autocomplete_fields = ("project", "vulnerability", "asset", "scan_session", "vuln_session")
	readonly_fields = ("created_at", "updated_at", "last_synced_at")


@admin.register(models.HuntSyncLog)
class HuntSyncLogAdmin(admin.ModelAdmin):
	list_display = (
		"started_at",
		"status",
		"project",
		"total_processed",
		"created_count",
		"updated_count",
		"skipped_count",
		"duration_ms",
	)
	list_filter = ("status", "project")
	search_fields = ("error_message",)
	readonly_fields = (
		"started_at",
		"finished_at",
		"duration_ms",
		"total_processed",
		"created_count",
		"updated_count",
		"skipped_count",
		"error_message",
	)


@admin.register(models.HuntEnrichment)
class HuntEnrichmentAdmin(admin.ModelAdmin):
	list_display = ("cve", "source", "status", "fetched_at", "expires_at")
	list_filter = ("source", "status")
	search_fields = ("cve",)
	readonly_fields = ("fetched_at", "created_at", "updated_at")


@admin.register(models.HuntFindingEnrichment)
class HuntFindingEnrichmentAdmin(admin.ModelAdmin):
	list_display = ("finding", "enrichment", "relation", "last_synced_at")
	list_filter = ("relation",)
	search_fields = ("finding__vulnerability__title", "enrichment__cve")
	autocomplete_fields = ("finding", "enrichment")
	readonly_fields = ("linked_at", "last_synced_at")


@admin.register(models.HuntFindingSnapshot)
class HuntFindingSnapshotAdmin(admin.ModelAdmin):
	list_display = ("finding", "version", "captured_at")
	search_fields = ("finding__vulnerability__title", "finding__cve")
	readonly_fields = ("captured_at",)
	autocomplete_fields = ("finding",)
