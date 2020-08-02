import json
import unittest
import urllib3

from crawler import KM200Crawler
from http import HTTPStatus
from unittest.mock import MagicMock,call

class TestKM200Crawler(unittest.TestCase):

    def setUp(self):
        self.crawler = KM200Crawler('', '', '')

    def test_get_prometheus_metric_floatValue(self):
        data = json.loads('{"id": "/dhwCircuits/dhw1/actualTemp", "type": "floatValue", "writeable": 0, "recordable": 0, "value": 33.3, "unitOfMeasure": "C", "state": [{"open": -3276.8}, {"short": 3276.7}]}')
        actual = self.crawler.get_prometheus_metric(data)
        expected = 'km200_dhwCircuits_dhw1_actualTemp{unitOfMeasure="C"} 33.3\n'

        self.assertEqual(actual, expected)

    def test_get_prometheus_metric_stringValue_DateTime(self):
        data = json.loads('{"id": "/gateway/DateTime", "type": "stringValue", "writeable": 1, "recordable": 0, "value": "2020-08-02T19:18:13"}')
        actual = self.crawler.get_prometheus_metric(data)
        expected = 'km200_gateway_DateTime{value="2020-08-02T19:18:13"} 1\n'

        self.assertEqual(actual, expected)

    def test_query_stringValue(self):
        data = json.loads('{"type": "stringValue"}')
        self.crawler.pool_manager.request = MagicMock(return_value=urllib3.HTTPResponse(body=' ', status=200))
        self.crawler.decrypt_response_data = MagicMock(return_value=data)
        self.crawler.get_prometheus_metric = MagicMock()

        self.crawler.query('/foo/bar')

        self.crawler.pool_manager.request.assert_called_once()
        self.crawler.get_prometheus_metric.assert_called_once_with(data)

    def test_query_refEnum(self):
        data = json.loads('{"type": "refEnum","references":[{"uri":"a"},{"uri":"b"}]}')
        self.crawler.pool_manager.request = MagicMock(return_value=urllib3.HTTPResponse(body=' ', status=200))
        self.crawler.decrypt_response_data = MagicMock(return_value=data)

        query_org = self.crawler.query
        self.crawler.query = MagicMock()

        query_org('/foo/bar')

        self.crawler.pool_manager.request.assert_called_once()
        self.crawler.query.assert_called_with('b')

    def test_query_ignore_uri_gateway_firmware(self):
        self.crawler.pool_manager.request = MagicMock(return_value=urllib3.HTTPResponse(body=' ', status=200))
        self.crawler.query('/foo/bar/gateway/firmware')

        self.crawler.pool_manager.request.assert_not_called()

if __name__ == '__main__':
    unittest.main()
