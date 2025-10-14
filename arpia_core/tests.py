import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .models import Project, ProjectMembership


class ProjectModelTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(username="owner", password="secret123")

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

	def test_create_project_view_creates_membership(self):
		response = self.client.post(
			reverse("projects_create"),
			{
				"name": "Projeto Insider",
				"description": "Escopo inicial",
				"client": "ACME",
				"start": "2025-01-01T10:00",
				"end": "2025-01-10T10:00",
			},
		)
		project = Project.objects.get(name="Projeto Insider")

		self.assertRedirects(response, reverse("projects_edit", kwargs={"pk": project.pk}))
		self.assertEqual(project.owner, self.user)
		self.assertTrue(ProjectMembership.objects.filter(project=project, user=self.user, role="owner").exists())

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

		response = self.client.post(
			reverse("projects_share", kwargs={"pk": project.pk}),
			{"action": "add", "username": "guest", "role": ProjectMembership.Role.EDITOR},
		)

		self.assertRedirects(response, reverse("projects_share", kwargs={"pk": project.pk}))
		self.assertTrue(
			ProjectMembership.objects.filter(project=project, user=guest, role=ProjectMembership.Role.EDITOR).exists()
		)

	def test_share_view_updates_member_role(self):
		project = Project.objects.create(owner=self.user, name="Compart", description="", client_name="")
		ProjectMembership.objects.create(project=project, user=self.user, role=ProjectMembership.Role.OWNER)
		member = get_user_model().objects.create_user(username="member", password="secret123")
		membership = ProjectMembership.objects.create(project=project, user=member, role=ProjectMembership.Role.VIEWER)

		response = self.client.post(
			reverse("projects_share", kwargs={"pk": project.pk}),
			{"action": "update", "membership_id": membership.pk, "role": ProjectMembership.Role.EDITOR},
		)

		self.assertRedirects(response, reverse("projects_share", kwargs={"pk": project.pk}))
		membership.refresh_from_db()
		self.assertEqual(membership.role, ProjectMembership.Role.EDITOR)

	def test_share_view_revokes_member(self):
		project = Project.objects.create(owner=self.user, name="Compart", description="", client_name="")
		ProjectMembership.objects.create(project=project, user=self.user, role=ProjectMembership.Role.OWNER)
		member = get_user_model().objects.create_user(username="member2", password="secret123")
		membership = ProjectMembership.objects.create(project=project, user=member, role=ProjectMembership.Role.EDITOR)

		response = self.client.post(
			reverse("projects_share", kwargs={"pk": project.pk}),
			{"action": "remove", "membership_id": membership.pk},
		)

		self.assertRedirects(response, reverse("projects_share", kwargs={"pk": project.pk}))
		self.assertFalse(ProjectMembership.objects.filter(pk=membership.pk).exists())


class ProjectAPITests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(username="apiuser", password="secret123")
		self.other = get_user_model().objects.create_user(username="other", password="secret123")
		self.project = Project.objects.create(owner=self.user, name="Alpha", description="", client_name="")
		ProjectMembership.objects.create(project=self.project, user=self.user, role="owner")
		self.client = APIClient()

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
