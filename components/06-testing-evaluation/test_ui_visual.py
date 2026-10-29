"""Neutral saved-evidence visual projection, no model or broker execution."""
import copy
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_llm import APIConfig
from pp_web import create_app
from pp_tcp_relationships import analyse_tcp_exchanges

class VisualProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='packetpilot-visual-')
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'web', self.root / 'web')
        self.broker = Mock()
        self.app = create_app(self.root, config_loader=lambda: APIConfig('https://example.test','test',''),
                              test_mode=True, response_client=self.broker)
        self.client = TestClient(self.app)
        self.token = self.client.get('/api/config').json()['csrf']

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def new(self, sample='port-check'):
        result = self.client.post('/api/reviews', json={'sample':sample,'provider':'rules'},
                                  headers={'X-PacketPilot-Token':self.token})
        self.assertEqual(result.status_code,201)
        return result.json()

    def test_projection_matches_existing_relationship_function_without_mutation(self):
        review = self.new()
        before = copy.deepcopy(self.app.state.store.get(review['id']))
        result = self.client.get(f'/api/reviews/{review["id"]}/visual')
        self.assertEqual(result.status_code,200)
        data = result.json()
        self.assertTrue(data['supported'])
        self.assertEqual(data['capture_sha256'],review['evidence']['capture']['sha256'])
        self.assertEqual(data['relationships'],analyse_tcp_exchanges(review['evidence']))
        self.assertEqual(self.app.state.store.get(review['id']),before)
        self.broker.call.assert_not_called()
        self.assertNotIn('assessment',data['relationships'])
        self.assertNotIn('command',data['relationships'])

    def test_projection_references_only_its_own_saved_source(self):
        first,second = self.new(),self.new('normal')
        for review in (first,second):
            data = self.client.get(f'/api/reviews/{review["id"]}/visual').json()
            for exchange in data['relationships']['exchanges']:
                for reference in exchange['supporting_references']:
                    self.assertTrue(reference.startswith(review['evidence']['capture']['sha256']+':'))
        self.broker.call.assert_not_called()

    def test_missing_and_invalid_review_ids_do_not_reveal_or_execute(self):
        self.assertEqual(self.client.get(f'/api/reviews/{uuid.uuid4()}/visual').status_code,404)
        self.assertEqual(self.client.get('/api/reviews/not-a-uuid/visual').status_code,422)
        self.broker.call.assert_not_called()

    def test_new_frontend_assets_are_served_locally_with_security_headers(self):
        for path in ('/','/assets/ui-model.js','/assets/app.js','/assets/style.css',
                     '/assets/vendor/plex-sans.woff2','/assets/vendor/connection.svg'):
            response = self.client.get(path)
            self.assertEqual(response.status_code,200,path)
            self.assertIn("script-src 'self'",response.headers['content-security-policy'])
            self.assertEqual(response.headers['x-content-type-options'],'nosniff')
