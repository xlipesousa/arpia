from __future__ import annotations

import os
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from arpia_hunt.integrations import exploitdb_service, nvd_service, vulners_service
from arpia_hunt.integrations.base import IntegrationError


class NvdServiceTests(SimpleTestCase):
    def test_fetch_cve_uses_custom_endpoint_and_headers(self):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"status": "ok"}
        requests_mock = mock.Mock(get=mock.Mock(return_value=response))

        with mock.patch("arpia_hunt.integrations.nvd_service.load_requests", return_value=requests_mock):
            with mock.patch.dict(
                os.environ,
                {
                    "ARPIA_HUNT_NVD_URL": "https://nvd.example/api",
                    "ARPIA_HUNT_NVD_API_KEY": "secret",
                    "ARPIA_HUNT_NVD_TIMEOUT": "3.5",
                },
                clear=False,
            ):
                payload = nvd_service.fetch_cve("CVE-2024-1234")

        self.assertEqual(payload, {"status": "ok"})
        requests_mock.get.assert_called_once_with(
            "https://nvd.example/api",
            params={"cveId": "CVE-2024-1234"},
            headers={"apiKey": "secret"},
            timeout=3.5,
        )

    def test_fetch_cve_wraps_errors(self):
        requests_mock = mock.Mock()
        requests_mock.get.side_effect = RuntimeError("boom")

        with mock.patch("arpia_hunt.integrations.nvd_service.load_requests", return_value=requests_mock):
            with self.assertRaises(IntegrationError) as ctx:
                nvd_service.fetch_cve("CVE-2024-9999")

        self.assertIn("Falha ao consultar NVD", str(ctx.exception))


class VulnersServiceTests(SimpleTestCase):
    def test_fetch_cve_includes_api_key_header(self):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"data": {"id": "CVE-2024-1111"}}
        requests_mock = mock.Mock(get=mock.Mock(return_value=response))

        with mock.patch("arpia_hunt.integrations.vulners_service.load_requests", return_value=requests_mock):
            with mock.patch.dict(
                os.environ,
                {
                    "ARPIA_HUNT_VULNERS_API_KEY": "vk-123",
                },
                clear=False,
            ):
                payload = vulners_service.fetch_cve("CVE-2024-1111")

        self.assertEqual(payload["data"]["id"], "CVE-2024-1111")
        requests_mock.get.assert_called_once()
        called_headers = requests_mock.get.call_args.kwargs["headers"]
        self.assertEqual(called_headers["X-ApiKey"], "vk-123")

    def test_fetch_cve_handles_timeout_parse(self):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"data": {"id": "CVE-2024-5555"}}
        requests_mock = mock.Mock(get=mock.Mock(return_value=response))

        with mock.patch("arpia_hunt.integrations.vulners_service.load_requests", return_value=requests_mock):
            with mock.patch.dict(
                os.environ,
                {"ARPIA_HUNT_VULNERS_TIMEOUT": "invalid"},
                clear=False,
            ):
                vulners_service.fetch_cve("CVE-2024-5555")

        # Timeout inválido cai no fallback 10.0
        self.assertEqual(requests_mock.get.call_args.kwargs["timeout"], 10.0)

    def test_fetch_cve_wraps_errors(self):
        requests_mock = mock.Mock()
        requests_mock.get.side_effect = RuntimeError("boom vulners")

        with mock.patch("arpia_hunt.integrations.vulners_service.load_requests", return_value=requests_mock):
            with self.assertRaises(IntegrationError) as ctx:
                vulners_service.fetch_cve("CVE-2024-2222")

        self.assertIn("Vulners", str(ctx.exception))


class ExploitDbServiceTests(SimpleTestCase):
    def test_search_cve_parses_json(self):
        process = SimpleNamespace(stdout='{"RESULTS_EXPLOIT": []}')

        with mock.patch("subprocess.run", return_value=process) as run_mock:
            payload = exploitdb_service.search_cve("CVE-2024-0001")

        self.assertEqual(payload, {"RESULTS_EXPLOIT": []})
        run_mock.assert_called_once()

    def test_search_cve_handles_missing_binary(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("searchsploit")):
            with self.assertRaises(IntegrationError) as ctx:
                exploitdb_service.search_cve("CVE-2024-0002")

        self.assertFalse(ctx.exception.retriable)
        self.assertIn("não encontrado", str(ctx.exception))

    def test_search_cve_reports_invalid_json(self):
        process = SimpleNamespace(stdout="{{invalid json}")

        with mock.patch("subprocess.run", return_value=process):
            with self.assertRaises(IntegrationError) as ctx:
                exploitdb_service.search_cve("CVE-2024-0003")

        self.assertFalse(ctx.exception.retriable)
        self.assertIn("JSON inválido", str(ctx.exception))
