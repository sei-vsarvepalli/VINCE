#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################
import json
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from vinny.views import CommVulReportAPIView


class _MockTemplate:
    def render(self, context=None):
        return "rendered"


class _MockS3Client:
    def copy_object(self, **kwargs):
        return {"ok": True}

    def put_object(self, **kwargs):
        return {"ok": True}


class _MockSESClient:
    def send_email(self, **kwargs):
        return {"MessageId": "test-message-id"}


class _MockCaseRequest:
    def __init__(self, user_file=None):
        self.user = None
        self.user_file = user_file

    def save(self):
        return None


class CommVulReportAPIViewTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = CommVulReportAPIView.as_view()
        self.user = User(username="tester@example.com")
        self.url = "/vince/comm/api/vulreport/"
        self.csaf_payload = {
            "document": {
                "publisher": {
                    "name": "Alice",
                    "issuing_authority": "Org",
                    "namespace": "mailto:alice@example.com",
                },
                "acknowledgments": [{"name": "Alice"}],
            },
            "product_tree": {
                "branches": [
                    {
                        "name": "Vendor A",
                        "branches": [{"name": "1.2.3", "product": {"name": "Product A"}}],
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "title": "Fallback title",
                    "notes": [
                        {"category": "description", "text": "Description from note"},
                        {"title": "Vulnerability Discovery Method", "text": "Discovery text"},
                    ],
                    "threats": [{"details": "Exploit details"}, {"details": "Impact details"}],
                    "involvements": [
                        {
                            "status": "contact_attempted",
                            "summary": "Reached out to vendor",
                            "date": "2026-01-01T00:00:00Z",
                        },
                        {"status": "open", "summary": "Public disclosure timeline"},
                    ],
                    "references": [
                        {"summary": "Publicly known reference", "url": "https://example.com/public"},
                        {"summary": "Actively exploited in the wild", "url": "https://example.com/exploit"},
                    ],
                    "metrics": [{"content": {"ssvc_v2": {"timestamp": "2026-01-01T00:00:00Z"}}}],
                }
            ],
            "x_extensions": [
                {
                    "content": {
                        "ics_impact": True,
                        "ai_ml_system": True,
                        "share_contact_with_vendor": True,
                        "multiple_vendors_impacted": True,
                        "multiple_vendors": ["Vendor B", "Vendor C"],
                        "Tracking_IDs": "VU#123456",
                        "private_comments": "Private note",
                    }
                }
            ],
        }

    def _mock_boto_client(self, name, *args, **kwargs):
        if name == "s3":
            return _MockS3Client()
        if name == "ses":
            return _MockSESClient()
        return SimpleNamespace()

    @patch("vinny.views.get_template", return_value=_MockTemplate())
    @patch("vinny.views.send_sns_json")
    @patch("vinny.views.send_sns")
    @patch("vinny.views.create_record_of_API_access")
    @patch("vinny.views.get_vrf_id", return_value="12345")
    @patch("vinny.views.boto3.client")
    @patch("vinny.views.CaseRequestForm.save")
    def test_application_json_csaf_success(
        self,
        mock_form_save,
        mock_boto_client,
        mock_get_vrf_id,
        mock_record_access,
        mock_send_sns,
        mock_send_sns_json,
        mock_get_template,
    ):
        mock_boto_client.side_effect = self._mock_boto_client
        mock_form_save.side_effect = lambda *args, **kwargs: _MockCaseRequest()

        request = self.factory.post(self.url, data=self.csaf_payload, format="json")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["vrf_id"].endswith("12345"))

    @patch("vinny.views.get_template", return_value=_MockTemplate())
    @patch("vinny.views.send_sns_json")
    @patch("vinny.views.send_sns")
    @patch("vinny.views.create_record_of_API_access")
    @patch("vinny.views.get_vrf_id", return_value="12345")
    @patch("vinny.views.boto3.client")
    @patch("vinny.views.CaseRequestForm.save")
    def test_multipart_csaf_with_file_success(
        self,
        mock_form_save,
        mock_boto_client,
        mock_get_vrf_id,
        mock_record_access,
        mock_send_sns,
        mock_send_sns_json,
        mock_get_template,
    ):
        mock_boto_client.side_effect = self._mock_boto_client

        def _save_form(form, commit=False):
            return _MockCaseRequest(user_file=form.cleaned_data.get("user_file"))

        mock_form_save.side_effect = _save_form
        upload = SimpleUploadedFile("sample.txt", b"sample data", content_type="text/plain")
        request = self.factory.post(
            self.url,
            data={"csaf": json.dumps(self.csaf_payload), "user_file": upload},
            format="multipart",
        )
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(payload["status"], "success")

    def test_malformed_csaf_json_returns_400(self):
        request = self.factory.post(self.url, data={"csaf": '{"document":'}, format="multipart")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 400)
        self.assertIn("csaf", payload["errors"])

    @patch("vinny.views.get_template", return_value=_MockTemplate())
    @patch("vinny.views.send_sns_json")
    @patch("vinny.views.send_sns")
    @patch("vinny.views.create_record_of_API_access")
    @patch("vinny.views.get_vrf_id", return_value="12345")
    @patch("vinny.views.boto3.client")
    @patch("vinny.views.CaseRequestForm.save")
    def test_legacy_form_submission_still_works(
        self,
        mock_form_save,
        mock_boto_client,
        mock_get_vrf_id,
        mock_record_access,
        mock_send_sns,
        mock_send_sns_json,
        mock_get_template,
    ):
        mock_boto_client.side_effect = self._mock_boto_client
        mock_form_save.side_effect = lambda *args, **kwargs: _MockCaseRequest()

        legacy_data = {
            "contact_name": "Legacy User",
            "contact_email": "legacy@example.com",
            "product_name": "Legacy Product",
            "product_version": "1.0",
            "vul_description": "Description",
            "vul_exploit": "Exploit",
            "vul_impact": "Impact",
            "vul_discovery": "Discovery",
            "vul_public": "False",
            "vul_exploited": "False",
            "vul_disclose": "False",
            "share_release": "True",
            "credit_release": "True",
            "comm_attempt": "False",
            "multiplevendors": "False",
        }

        request = self.factory.post(self.url, data=legacy_data, format="multipart")
        force_authenticate(request, user=self.user)

        response = self.view(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(payload["status"], "success")
