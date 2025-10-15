from django.contrib import admin

from .models import Asset, ObservedEndpoint, Project, ProjectMembership, Script


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
	list_display = ("name", "owner", "status", "created", "modified")
	search_fields = ("name", "owner__username", "owner__email", "client_name")
	list_filter = ("status", "visibility", "created")
	ordering = ("-created",)


@admin.register(ProjectMembership)
class ProjectMembershipAdmin(admin.ModelAdmin):
	list_display = ("project", "user", "role", "created_at")
	search_fields = ("project__name", "user__username", "user__email")
	list_filter = ("role", "created_at")
	autocomplete_fields = ("project", "user", "invited_by")


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
	list_display = ("identifier", "project", "category", "last_seen")
	search_fields = ("identifier", "project__name", "hostnames")
	list_filter = ("category",)
	autocomplete_fields = ("project",)


@admin.register(ObservedEndpoint)
class ObservedEndpointAdmin(admin.ModelAdmin):
	list_display = ("ip", "port", "service", "source", "last_seen")
	search_fields = ("ip", "service", "source")
	list_filter = ("source", "proto")
	autocomplete_fields = ("asset",)


@admin.register(Script)
class ScriptAdmin(admin.ModelAdmin):
	list_display = ("name", "kind", "owner", "filename", "updated_at")
	list_filter = ("kind", "updated_at")
	search_fields = ("name", "filename", "owner__username")
	autocomplete_fields = ("owner",)
	ordering = ("name",)
