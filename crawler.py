import argparse
import base64
import json
import logging
import urllib3

from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD5
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer

BUDERUS_MAGIC_BYTES = '867845e97c4e29dce522b9a7d3a3e07b152bffadddbed7f5ffd842e9895ad1e4'
BUDERUS_KNOWN_APIS = ['/dhwCircuits', '/gateway', '/heatSources', '/heatingCircuits', '/notifications', '/recordings', '/solarCircuits', '/system']


class KM200Crawler(BaseHTTPRequestHandler):

    def __init__(self, km200_host, gateway_password, private_password):
        self.km200_host = km200_host
        self.cipher = AES.new(self.create_decryption_key(gateway_password, private_password), AES.MODE_ECB)
        self.pool_manager = urllib3.PoolManager()

    def __call__(self, *args):
        """ Handle a request https://stackoverflow.com/questions/21631799/how-can-i-pass-parameters-to-a-requesthandler/58909293#58909293"""
        super().__init__(*args)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=UTF-8")
        self.end_headers()

        for api in [self.path] if self.path != '/' else BUDERUS_KNOWN_APIS:
            result = self.query(f'http://{self.km200_host}{api}')
            if result:
                self.wfile.write(bytes(result, "utf-8"))

    def log_message(self, format, *args):
        return

    def log_request(self, *args):
        return

    def create_decryption_key(self, gateway_password, private_password):
        part1 = MD5.new()
        part1.update(gateway_password.replace('-', '').encode() + bytes.fromhex(BUDERUS_MAGIC_BYTES))

        part2 = MD5.new()
        part2.update(bytes.fromhex(BUDERUS_MAGIC_BYTES) + private_password.encode())

        return part1.digest()[:32] + part2.digest()[:32]

    def decrypt_response_data(self, data):
        decoded = base64.b64decode(data)
        decrypted_bytes = self.cipher.decrypt(decoded)
        logging.debug(decrypted_bytes)

        plaintext = decrypted_bytes.decode('UTF-8').replace('\0', '')
        return json.loads(plaintext)

    def query(self, uri):
        try:
            if uri.endswith('gateway/firmware'):
                return

            response = self.pool_manager.request('GET', uri, headers={'User-Agent': 'TeleHeater', 'Content-type': 'application/json; charset=utf-8'})

            if response.status == HTTPStatus.OK:
                response_json = self.decrypt_response_data(response.data)

                if response_json['type'] == 'refEnum':
                    results = ''

                    for reference in response_json['references']:
                        result = self.query(reference['uri'])

                        if result:
                            results += result

                    return results

                else:
                    return self.get_prometheus_metric(response_json)

            else:
                logging.warning(f"'{uri}' request was not successfull: {response.status} {HTTPStatus(response.status).phrase}")

        except Exception:
            logging.exception(f"'{uri}' error while processing")

    def get_prometheus_metric(self, json):
        metric_name = f"km200{json['id'].replace('/','_')}"

        if json['type'] == 'stringValue':

            if 'allowedValues' in json and json['allowedValues'] in [["off", "on"], ["false", "true"], ["INACTIVE", "ACTIVE"], ["stop", "start"]]:
                return f"{metric_name} {'1' if json['value'].lower() in ['on', 'true', 'active', 'start'] else '0'}\n"

            else:
                return f"{metric_name}{{value=\"{json['value']}\"}} 1\n"

        elif json['type'] == 'floatValue':
            return f"{metric_name}{{unitOfMeasure=\"{json['unitOfMeasure']}\"}} {json['value']}\n"

        else:
            logging.warning(f"Unhandled data type: {json}")


def get_cli_args():
    parser = argparse.ArgumentParser(description='Crawls a Bosch KM200 endpoint and provides the data on a http endpoint for prometheus to collect. The crawler collects data per request.')

    parser.add_argument('--km200_host',             required=True,              help='The private password previously created in the smartphone app')
    parser.add_argument('--km200_gateway_password', required=True,              help='The gateway password of the Web KM200 device as printed on a sticker on the outside of that device')
    parser.add_argument('--km200_private_password', required=True,              help='The private password previously created in the smartphone app')
    parser.add_argument('--web_listen_address',     default='localhost:9201',   help='Address on which to expose metrics and web interface')
    parser.add_argument('--log',                    default=logging.ERROR,      help='Log level')

    return parser.parse_args()


if __name__ == "__main__":
    args = get_cli_args()
    host, port = args.web_listen_address.split(':')

    logging.basicConfig(level=args.log)

    print(f'Server {host}:{port} starts...')

    handler = KM200Crawler(args.km200_host, args.km200_gateway_password, args.km200_private_password)
    TCPServer.allow_reuse_address = True
    server = TCPServer((host, int(port)), handler)

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        pass

    server.server_close()

    print(f'Server {host}:{port} stopped!')
