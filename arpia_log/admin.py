from django.contrib import admin

from .models import LogEntry


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
	list_display = ("timestamp", "source_app", "event_type", "severity", "project_ref")
	search_fields = ("message", "source_app", "event_type", "project_ref", "user_ref")
	list_filter = ("severity", "source_app", "ingestion_channel")
	ordering = ("-timestamp",)
