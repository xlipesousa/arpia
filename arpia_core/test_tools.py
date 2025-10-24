from django.contrib.auth import get_user_model
from django.test import TestCase

from .models import Tool
from .tool_registry import DEFAULT_TOOLS, sync_default_tools_for_user
from .views import build_project_macros


class ToolRegistryTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="tooltester",
            email="tooltester@example.com",
            password="pass1234",
        )

    def test_sync_provisions_default_tools(self):
        tools = list(Tool.objects.for_user(self.user))
        self.assertEqual(len(tools), len(DEFAULT_TOOLS))
        slugs = {tool.slug for tool in tools}
        expected = {definition.slug for definition in DEFAULT_TOOLS}
        self.assertSetEqual(slugs, expected)
        for definition in DEFAULT_TOOLS:
            tool = Tool.objects.get(owner=self.user, slug=definition.slug)
            self.assertEqual(tool.path, definition.path)
            self.assertEqual(tool.name, definition.name)
            self.assertEqual(tool.category, definition.category)

    def test_sync_preserves_custom_paths(self):
        Tool.objects.for_user(self.user)  # garante criação inicial
        Tool.objects.filter(owner=self.user, slug="rustscan").update(path="/opt/custom/rustscan")
        sync_default_tools_for_user(self.user)
        tool = Tool.objects.get(owner=self.user, slug="rustscan")
        self.assertEqual(tool.path, "/opt/custom/rustscan")

    def test_macros_include_tool_paths(self):
        tools = Tool.objects.for_user(self.user)
        macros = build_project_macros(self.user, None)
        for tool in tools:
            self.assertIn(tool.macro_key, macros)
            self.assertEqual(macros[tool.macro_key], tool.path)
