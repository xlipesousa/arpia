from django.contrib import admin

from .models import ChatMessage, ChatSession, Provider, ProviderCredential


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
	list_display = ("name", "slug", "base_url", "is_active", "created_at")
	list_filter = ("is_active",)
	search_fields = ("name", "slug")


@admin.register(ProviderCredential)
class ProviderCredentialAdmin(admin.ModelAdmin):
	list_display = ("provider", "label", "owner", "masked_api_key", "last_used_at", "created_at")
	list_filter = ("provider",)
	search_fields = ("label", "owner__username")


class ChatMessageInline(admin.TabularInline):
	model = ChatMessage
	extra = 0
	readonly_fields = ("role", "content", "token_count", "created_at")


@admin.register(ChatSession)
class ChatSessionAdmin(admin.ModelAdmin):
	list_display = ("id", "provider", "owner", "project", "title", "is_active", "created_at")
	list_filter = ("provider", "is_active")
	search_fields = ("id", "title", "owner__username")
	inlines = [ChatMessageInline]


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
	list_display = ("session", "role", "token_count", "created_at")
	list_filter = ("role",)
	search_fields = ("session__id", "content")
