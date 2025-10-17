from django.contrib import admin

from .models import ScanSession, ScanTask, ScanFinding


@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
	list_display = ("reference", "title", "project", "status", "created_at", "started_at", "finished_at")
	list_filter = ("status", "project")
	search_fields = ("reference", "title", "project__name")
	ordering = ("-created_at",)


@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
	list_display = ("session", "order", "name", "kind", "status", "started_at", "finished_at")
	list_filter = ("kind", "status")
	search_fields = ("name", "session__reference")
	ordering = ("session", "order")


@admin.register(ScanFinding)
class ScanFindingAdmin(admin.ModelAdmin):
	list_display = ("session", "kind", "title", "severity", "created_at")
	list_filter = ("kind", "severity")
	search_fields = ("title", "session__reference")
	ordering = ("session", "order", "id")
