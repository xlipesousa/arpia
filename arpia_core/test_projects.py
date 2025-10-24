import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from arpia_log.models import LogEntry

from .models import Project, ProjectMembership


class ProjectModelTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(username="owner", password="secret123")
		LogEntry.objects.all().delete()

	def test_slug_is_unique_per_owner(self):
		project1 = Project.objects.create(owner=self.user, name="Infra", description="", client_name="")
		project2 = Project.objects.create(owner=self.user, name="Infra", description="", client_name="")

		self.assertNotEqual(project1.slug, project2.slug)

	def test_slug_can_repeat_for_different_owners(self):
		other = get_user_model().objects.create_user(username="guest", password="secret123")
		project1 = Project.objects.create(owner=self.user, name="Blue", description="", client_name="")
		project2 = Project.objects.create(owner=other, name="Blue", description="", client_name="")

		self.assertEqual(project1.slug, project2.slug)


class ProjectViewTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(username="alice", password="secret123")
		self.client.login(username="alice", password="secret123")
		LogEntry.objects.all().delete()

	def test_create_project_view_creates_membership(self):
		response = self.client.post(
			reverse("projects_create"),
			{
				"name": "Projeto Insider",
				"description": "Escopo inicial",
				"client": "ACME",
				"start": "2025-01-01T10:00",
				"end": "2025-01-10T10:00",
				"ports": "80, 443/tcp, 53/udp",
			},
		)
		project = Project.objects.get(name="Projeto Insider")

		self.assertRedirects(response, reverse("projects_edit", kwargs={"pk": project.pk}))
		self.assertEqual(project.owner, self.user)
		self.assertEqual(project.ports, "80/tcp\n443/tcp\n53/udp")
		self.assertTrue(ProjectMembership.objects.filter(project=project, user=self.user, role="owner").exists())
		self.assertTrue(
			LogEntry.objects.filter(event_type="PROJECT_CREATED", details__project_id=str(project.pk)).exists()
		)

	def test_edit_view_validates_port_entries(self):
		project = Project.objects.create(owner=self.user, name="Projeto", description="", client_name="", ports="22/tcp")

		response = self.client.post(
			reverse("projects_edit", kwargs={"pk": project.pk}),
			{
				"name": "Projeto",
				"description": "",
				"client": "",
				"start": "",
				"end": "",
				"hosts": "",
				"protected_hosts": "",
				"networks": "",
				"ports": "70000/tcp, 21/ftp",
				"credentials_json": "[]",
			},
		)

		project.refresh_from_db()
		self.assertEqual(response.status_code, 200)
		self.assertIn("Entradas de porta inválidas", response.content.decode())
		self.assertEqual(project.ports, "22/tcp")

	def test_edit_view_normalizes_port_entries(self):
		project = Project.objects.create(owner=self.user, name="Projeto", description="", client_name="")

		response = self.client.post(
			reverse("projects_edit", kwargs={"pk": project.pk}),
			{
				"name": "Projeto",
				"description": "",
				"client": "",
				"start": "",
				"end": "",
				"hosts": "",
				"protected_hosts": "",
				"networks": "",
				"ports": "443; 53/UDP, 22",
				"credentials_json": "[]",
			},
		)

		project.refresh_from_db()
		self.assertRedirects(response, reverse("projects_edit", kwargs={"pk": project.pk}))
		self.assertEqual(project.ports, "443/tcp\n53/udp\n22/tcp")

	def test_edit_view_requires_owner(self):
		project = Project.objects.create(owner=self.user, name="Proj", description="", client_name="")
		other = get_user_model().objects.create_user(username="bob", password="secret123")

		self.client.logout()
		self.client.login(username="bob", password="secret123")

		response = self.client.post(
			reverse("projects_edit", kwargs={"pk": project.pk}),
			{"name": "Proj 2"},
		)

		self.assertRedirects(response, reverse("projects_list"))
		project.refresh_from_db()
		self.assertEqual(project.name, "Proj")

	def test_share_view_adds_member(self):
		project = Project.objects.create(owner=self.user, name="Compart", description="", client_name="")
		ProjectMembership.objects.create(project=project, user=self.user, role=ProjectMembership.Role.OWNER)
		guest = get_user_model().objects.create_user(username="guest", password="secret123")
		LogEntry.objects.all().delete()

		response = self.client.post(
			reverse("projects_share", kwargs={"pk": project.pk}),
			{"action": "add", "username": "guest", "role": ProjectMembership.Role.EDITOR},
		)

		self.assertRedirects(response, reverse("projects_share", kwargs={"pk": project.pk}))
		self.assertTrue(
			ProjectMembership.objects.filter(project=project, user=guest, role=ProjectMembership.Role.EDITOR).exists()
		)
		self.assertTrue(
			LogEntry.objects.filter(
				event_type="PROJECT_MEMBER_ADDED",
				details__project_id=str(project.pk),
				details__member_id=guest.pk,
			).exists()
		)

	def test_share_view_updates_member_role(self):
		project = Project.objects.create(owner=self.user, name="Compart", description="", client_name="")
		ProjectMembership.objects.create(project=project, user=self.user, role=ProjectMembership.Role.OWNER)
		member = get_user_model().objects.create_user(username="member", password="secret123")
		membership = ProjectMembership.objects.create(project=project, user=member, role=ProjectMembership.Role.VIEWER)
		LogEntry.objects.all().delete()

		response = self.client.post(
			reverse("projects_share", kwargs={"pk": project.pk}),
			{"action": "update", "membership_id": membership.pk, "role": ProjectMembership.Role.EDITOR},
		)

		self.assertRedirects(response, reverse("projects_share", kwargs={"pk": project.pk}))
		membership.refresh_from_db()
		self.assertEqual(membership.role, ProjectMembership.Role.EDITOR)
		self.assertTrue(
			LogEntry.objects.filter(
				event_type="PROJECT_MEMBER_UPDATED",
				details__membership_id=membership.pk,
				details__role__to=ProjectMembership.Role.EDITOR,
			).exists()
		)

	def test_share_view_revokes_member(self):
		project = Project.objects.create(owner=self.user, name="Compart", description="", client_name="")
		ProjectMembership.objects.create(project=project, user=self.user, role=ProjectMembership.Role.OWNER)
		member = get_user_model().objects.create_user(username="member2", password="secret123")
		membership = ProjectMembership.objects.create(project=project, user=member, role=ProjectMembership.Role.EDITOR)
		LogEntry.objects.all().delete()

		response = self.client.post(
			reverse("projects_share", kwargs={"pk": project.pk}),
			{"action": "remove", "membership_id": membership.pk},
		)

		self.assertRedirects(response, reverse("projects_share", kwargs={"pk": project.pk}))
		self.assertFalse(ProjectMembership.objects.filter(pk=membership.pk).exists())
		self.assertTrue(
			LogEntry.objects.filter(
				event_type="PROJECT_MEMBER_REMOVED",
				details__project_id=str(project.pk),
				details__member_id=member.pk,
			).exists()
		)


class ProjectAPITests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(username="apiuser", password="secret123")
		self.other = get_user_model().objects.create_user(username="other", password="secret123")
		self.project = Project.objects.create(owner=self.user, name="Alpha", description="", client_name="")
		ProjectMembership.objects.create(project=self.project, user=self.user, role="owner")
		self.client = APIClient()
		LogEntry.objects.all().delete()

	def test_project_list_returns_only_user_projects(self):
		foreign = Project.objects.create(owner=self.other, name="Foreign", description="", client_name="")
		ProjectMembership.objects.create(project=foreign, user=self.other, role="owner")

		self.client.login(username="apiuser", password="secret123")
		response = self.client.get(reverse("project-list"))

		self.assertEqual(response.status_code, 200)
		data = response.json()
		ids = {item["id"] for item in data}
		self.assertIn(str(self.project.id), ids)
		self.assertNotIn(str(foreign.id), ids)

	def test_project_create_sets_owner(self):
		self.client.login(username="apiuser", password="secret123")
		payload = {"name": "Beta", "description": "", "client_name": "", "status": Project.Status.DRAFT}
		response = self.client.post(reverse("project-list"), data=json.dumps(payload), content_type="application/json")

		self.assertEqual(response.status_code, 201)
		created = Project.objects.get(name="Beta")
		self.assertEqual(created.owner, self.user)
		self.assertTrue(ProjectMembership.objects.filter(project=created, user=self.user, role="owner").exists())
		self.assertTrue(
			LogEntry.objects.filter(event_type="PROJECT_CREATED", details__project_id=str(created.pk)).exists()
		)

	def test_project_update_logs_changes(self):
		self.client.login(username="apiuser", password="secret123")
		payload = {"name": "Alpha Updated"}
		response = self.client.patch(
			reverse("project-detail", kwargs={"pk": self.project.pk}),
			data=json.dumps(payload),
			content_type="application/json",
		)

		self.assertEqual(response.status_code, 200)
		self.project.refresh_from_db()
		self.assertEqual(self.project.name, "Alpha Updated")
		self.assertTrue(
			LogEntry.objects.filter(
				event_type="PROJECT_UPDATED",
				details__changes__name__to="Alpha Updated",
				details__project_id=str(self.project.pk),
			).exists()
		)

	def test_project_delete_logs_event(self):
		self.client.login(username="apiuser", password="secret123")
		response = self.client.delete(reverse("project-detail", kwargs={"pk": self.project.pk}))

		self.assertEqual(response.status_code, 204)
		self.assertFalse(Project.objects.filter(pk=self.project.pk).exists())
		self.assertTrue(
			LogEntry.objects.filter(
				event_type="PROJECT_DELETED",
				details__project_id=str(self.project.pk),
			).exists()
		)
