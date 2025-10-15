import json
import shutil

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from .forms import ScriptForm
from .models import Project, Script, Tool, Wordlist
from .script_registry import get_default_catalog
from .views import SCRIPTS_BASE, build_project_macros, render_script_with_macros, sync_default_scripts


class ScriptFormTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user("formuser", password="secret123")

	def test_requires_unique_filename_per_owner(self):
		Script.objects.create(
			owner=self.user,
			name="Meu script",
			slug="meu-script",
			description="",
			filename="scan.sh",
			content="#",
		)

		form = ScriptForm(
			data={
				"name": "Outro nome",
				"description": "",
				"filename": "scan.sh",
				"content": "echo ok",
			},
			owner=self.user,
		)
		self.assertFalse(form.is_valid())
		self.assertIn("filename", form.errors)

	def test_safe_filename_validation(self):
		form = ScriptForm(
			data={
				"name": "Scan",
				"description": "",
				"filename": "..",
				"content": "echo 1",
			},
			owner=self.user,
		)
		self.assertFalse(form.is_valid())
		self.assertIn("filename", form.errors)

	def test_clean_filename_sanitizes_path_traversal(self):
		form = ScriptForm(
			data={
				"name": "Scan",
				"description": "",
				"filename": "../../evil.sh",
				"content": "echo 1",
			},
			owner=self.user,
		)
		self.assertTrue(form.is_valid())
		self.assertEqual(form.cleaned_data["filename"], "evil.sh")


class ScriptSyncTests(TestCase):
	def setUp(self):
		self.catalog = get_default_catalog()

	def test_sync_creates_defaults(self):
		sync_default_scripts()
		for entry in self.catalog:
			self.assertTrue(
				Script.objects.filter(owner__isnull=True, slug=entry.slug, filename=entry.filename).exists()
			)

	def test_sync_updates_content(self):
		sync_default_scripts()
		first = self.catalog[0]
		script = Script.objects.get(slug=first.slug, owner__isnull=True)
		script.content = "old"
		script.save(update_fields=["content"])

		sync_default_scripts()
		script.refresh_from_db()
		self.assertNotEqual(script.content, "old")


class ScriptViewsTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user("viewer", password="secret123")
		self.client = Client()
		self.client.login(username="viewer", password="secret123")
		sync_default_scripts()

	def tearDown(self):
		user_dir = SCRIPTS_BASE / "user"
		if user_dir.exists():
			shutil.rmtree(user_dir)
		super().tearDown()

	def test_list_view_returns_defaults(self):
		response = self.client.get(reverse("scripts_list"))
		self.assertEqual(response.status_code, 200)
		scripts = response.context["scripts"]
		filenames = {item["filename"] for item in scripts}
		for entry in get_default_catalog():
			self.assertIn(entry.filename, filenames)

	def test_create_view_persists_user_script(self):
		payload = {
			"name": "Varredura",
			"description": "Teste",
			"filename": "scan_user.sh",
			"content": "echo oi",
		}
		response = self.client.post(reverse("scripts_new"), data=payload)
		self.assertEqual(response.status_code, 302)
		self.assertTrue(Script.objects.filter(owner=self.user, filename="scan_user.sh").exists())

	def test_run_view_renders_macros(self):
		project = Project.objects.create(owner=self.user, name="Projeto X", description="", client_name="")
		Script.objects.create(
			owner=self.user,
			name="Custom",
			slug="custom",
			description="",
			filename="custom.sh",
			content="ping {{PROJECT_NAME}}",
			kind=Script.Kind.USER,
		)
		user_script = Script.objects.get(owner=self.user, filename="custom.sh")
		response = self.client.get(reverse("scripts_run", kwargs={"pk": user_script.pk}), data={"project": project.pk})
		self.assertEqual(response.status_code, 200)
		data = json.loads(response.content)
		self.assertIn("Projeto X", data["content"])


class MacroHelpersTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user("macro", password="secret123")

	def test_build_project_macros_handles_empty(self):
		macros = build_project_macros(self.user, None)
		self.assertEqual(macros["PROJECT_NAME"], "")
		self.assertEqual(macros["CREDENTIALS_JSON"], "[]")

	def test_render_script_with_macros_substitutes(self):
		project = Project.objects.create(owner=self.user, name="Proj", description="", client_name="")
		macros = build_project_macros(self.user, project)
		rendered = render_script_with_macros("echo {{PROJECT_NAME}}", macros)
		self.assertIn("Proj", rendered)

	def test_tool_macros_are_included(self):
		Tool.objects.create(owner=self.user, name="Nmap", path="/opt/nmap")
		macros = build_project_macros(self.user, None)
		self.assertIn("TOOL_NMAP", macros)
		self.assertEqual(macros["TOOL_NMAP"], "/opt/nmap")

	def test_wordlist_macros_are_included(self):
		Wordlist.objects.create(owner=self.user, name="rockyou", path="/wordlists/rockyou.txt")
		macros = build_project_macros(self.user, None)
		self.assertIn("WORDLIST_ROCKYOU", macros)
		self.assertEqual(macros["WORDLIST_ROCKYOU"], "/wordlists/rockyou.txt")


class ToolViewsTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user("tooluser", password="secret123")
		self.client = Client()
		self.client.login(username="tooluser", password="secret123")

	def test_tool_create_view(self):
		payload = {
			"name": "Nmap",
			"description": "Scanner",
			"path": "/usr/bin/nmap",
			"category": "scanner",
		}
		response = self.client.post(reverse("tools_add"), data=payload)
		self.assertEqual(response.status_code, 302)
		self.assertTrue(Tool.objects.filter(owner=self.user, name="Nmap").exists())

	def test_tool_list_displays_macro(self):
		Tool.objects.create(owner=self.user, name="Nmap", path="/usr/bin/nmap")
		response = self.client.get(reverse("tools_list"))
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, "TOOL_NMAP")


class WordlistViewsTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user("worduser", password="secret123")
		self.client = Client()
		self.client.login(username="worduser", password="secret123")

	def test_wordlist_create_view(self):
		payload = {
			"name": "rockyou",
			"description": "Lista famosa",
			"path": "/wordlists/rockyou.txt",
			"category": "passwords",
			"tags": "passwords, default",
		}
		response = self.client.post(reverse("wordlists_add"), data=payload)
		self.assertEqual(response.status_code, 302)
		self.assertTrue(Wordlist.objects.filter(owner=self.user, name="rockyou").exists())

	def test_wordlist_list_displays_macro(self):
		Wordlist.objects.create(owner=self.user, name="rockyou", path="/wordlists/rockyou.txt")
		response = self.client.get(reverse("tools_list"))
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, "WORDLIST_ROCKYOU")
