import base64
import json
import logging
import os
import time
from http import HTTPStatus

import urllib3
from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD5
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY

BUDERUS_MAGIC_BYTES = '867845e97c4e29dce522b9a7d3a3e07b152bffadddbed7f5ffd842e9895ad1e4'
# BUDERUS_KNOWN_APIS = ['/dhwCircuits', '/gateway', '/heatSources', '/heatingCircuits', '/notifications', '/recordings', '/solarCircuits', '/system']
# BUDERUS_KNOWN_APIS = ['/dhwCircuits', '/gateway', '/heatSources', '/heatingCircuits', '/notifications', '/recordings', '/system']

BUDERUS_KNOWN_APIS = [
    '/dhwCircuits/dhw1/actualTemp',
    '/dhwCircuits/dhw1/charge',
    '/dhwCircuits/dhw1/chargeDuration',
    '/dhwCircuits/dhw1/currentSetpoint',
    '/dhwCircuits/dhw1/holidayMode/activated',
    '/dhwCircuits/dhw1/operationMode',
    '/dhwCircuits/dhw1/singleChargeSetpoint',
    '/dhwCircuits/dhw1/status',
    '/dhwCircuits/dhw1/waterFlow',
    '/dhwCircuits/dhw1/workingTime',
    '/gateway/DateTime',
    '/gateway/instAccess',
    '/gateway/instWriteAccess',
    '/gateway/update/status',
    '/gateway/uuid',
    '/gateway/versionFirmware',
    '/gateway/versionHardware',
    '/heatSources/CHpumpModulation',
    '/heatSources/ChimneySweeper',
    '/heatSources/actualCHPower',
    '/heatSources/actualDHWPower',
    '/heatSources/actualModulation',
    '/heatSources/actualSupplyTemperature',
    '/heatSources/applianceSupplyTemperature',
    '/heatSources/burnerModulationSetpoint',
    '/heatSources/burnerPowerSetpoint',
    '/heatSources/chimneyTemperature',
    '/heatSources/energyMonitoring/consumption',
    '/heatSources/energyMonitoring/correctionFactor',
    '/heatSources/energyMonitoring/maxTankLevel',
    '/heatSources/energyMonitoring/minTankLevel',
    '/heatSources/energyMonitoring/startDateTime',
    '/heatSources/energyMonitoring/tankLevel',
    '/heatSources/flameStatus',
    '/heatSources/hs1/actualModulation',
    '/heatSources/hs1/actualPower',
    '/heatSources/hs1/flameStatus',
    '/heatSources/nominalCHPower',
    '/heatSources/nominalDHWPower',
    '/heatSources/numberOfStarts',
    '/heatSources/powerSetpoint',
    '/heatSources/returnTemperature',
    '/heatSources/supplyTemperatureSetpoint',
    '/heatSources/systemPressure',
    '/heatSources/workingTime/centralHeating',
    '/heatSources/workingTime/secondBurner',
    '/heatSources/workingTime/totalSystem',
    '/heatingCircuits/hc1/activeSwitchProgram',
    '/heatingCircuits/hc1/currentRoomSetpoint',
    '/heatingCircuits/hc1/currentSuWiMode',
    '/heatingCircuits/hc1/holidayMode/activated',
    '/heatingCircuits/hc1/operationMode',
    '/heatingCircuits/hc1/pumpModulation',
    '/heatingCircuits/hc1/roomtemperature',
    '/heatingCircuits/hc1/status',
    '/heatingCircuits/hc1/suWiSwitchMode',
    '/heatingCircuits/hc1/suWiThreshold',
    '/heatingCircuits/hc1/supplyTemperatureSetpoint',
    '/heatingCircuits/hc1/switchProgramMode',
    '/heatingCircuits/hc1/temperatureLevels/comfort2',
    '/heatingCircuits/hc1/temperatureLevels/eco',
    '/heatingCircuits/hc1/temporaryRoomSetpoint',
    '/system/appliance/actualSupplyTemperature',
    '/system/brand',
    '/system/bus',
    '/system/healthStatus',
    '/system/holidayModes/hm1/dhwMode',
    '/system/holidayModes/hm1/fixTemperature',
    '/system/holidayModes/hm1/hcMode',
    '/system/holidayModes/hm1/startStop',
    '/system/holidayModes/hm2/dhwMode',
    '/system/holidayModes/hm2/hcMode',
    '/system/holidayModes/hm2/startStop',
    '/system/holidayModes/hm3/dhwMode',
    '/system/holidayModes/hm3/hcMode',
    '/system/holidayModes/hm3/startStop',
    '/system/holidayModes/hm4/dhwMode',
    '/system/holidayModes/hm4/hcMode',
    '/system/holidayModes/hm4/startStop',
    '/system/holidayModes/hm5/dhwMode',
    '/system/holidayModes/hm5/hcMode',
    '/system/holidayModes/hm5/startStop',
    '/system/minOutdoorTemp',
    '/system/sensors/temperatures/chimney',
    '/system/sensors/temperatures/hotWater_t2',
    '/system/sensors/temperatures/outdoor_t1',
    '/system/sensors/temperatures/return',
    '/system/sensors/temperatures/supply_t1',
    '/system/sensors/temperatures/supply_t1_setpoint',
    '/system/sensors/temperatures/switch',
    '/system/systemType']

results = []

km200_host = os.environ['km200_host']
km200_gateway_password = os.environ['km200_gateway_password']
km200_private_password = os.environ['km200_private_password']
exporter_port = os.environ['exporter_port']
loglevel = os.environ['loglevel']


class KM200Crawler(object):

    def __init__(self, km200_host, gateway_password, private_password):
        self.km200_host = km200_host
        self.cipher = AES.new(self.create_decryption_key(gateway_password, private_password), AES.MODE_ECB)
        self.pool_manager = urllib3.PoolManager()

    def collect(self):
        print("crawler gestartet")

        g_temperature = GaugeMetricFamily("km200_temperature_c", 'km200 Temperatur Sensor in Grad Celsius',
                                          labels=['sensor'])
        g_power = GaugeMetricFamily("km200_power_kW", 'km200 Power Sensor in kW', labels=['sensor'])
        g_percent = GaugeMetricFamily("km200_percent", 'km200 Percent Sensor in %', labels=['sensor'])
        g_pressure = GaugeMetricFamily("km200_pressure_bar", 'km200 Pressure Sensor in Bar', labels=['sensor'])
        g_energy = GaugeMetricFamily("km200_energy_kWh", 'km200 Energy Sensor in kWh', labels=['sensor'])
        g_min = GaugeMetricFamily("km200_mins_", 'km200 Sensor in Minutes', labels=['sensor'])
        g_liter_per_min = GaugeMetricFamily("km200_liter_per_min", 'km200 Sensor in Liter per Minute',
                                            labels=['sensor'])

        g_info = GaugeMetricFamily("km200_system_info", 'km200 Energy Sensor in kWh', labels=['sensor', 'info'])

        g_state = GaugeMetricFamily("km200_state", 'km200 State Sensor', labels=['sensor'])

        for api in BUDERUS_KNOWN_APIS:
            self.query(f'http://{self.km200_host}{api}')

            for r in results:
                if r['type'] == "C":
                    g_temperature.add_metric([r['metric']], r['value'])

                elif r['type'] == "kW":
                    g_power.add_metric([r['metric']], r['value'])

                elif r['type'] == "%":
                    g_percent.add_metric([r['metric']], r['value'])

                elif r['type'] == "bar":
                    g_pressure.add_metric([r['metric']], r['value'])

                elif r['type'] == "kWh":
                    g_energy.add_metric([r['metric']], r['value'])

                elif r['type'] == "info":
                    g_info.add_metric([r['metric'], r['value']], 1)

                elif r['type'] == "state" or r['type'] == " ":
                    g_state.add_metric([r['metric']], r['value'])

                elif r['type'] == "l/min":
                    g_liter_per_min.add_metric([r['metric']], r['value'])

                elif r['type'] == "mins":
                    g_min.add_metric([r['metric']], r['value'])

                else:
                    print("other:", r)

            results.clear()

        yield g_temperature
        yield g_power
        yield g_percent
        yield g_pressure
        yield g_energy
        yield g_info
        yield g_liter_per_min
        yield g_min
        yield g_state

    def log_message(self, format, *args):
        return

    def log_request(self, *args):
        return

    def create_decryption_key(self, gateway_password, private_password):
        part1 = MD5.new()
        part1.update(gateway_password.replace('-', '').encode() + bytes.fromhex(BUDERUS_MAGIC_BYTES))

        part2 = MD5.new()
        part2.update(bytes.fromhex(BUDERUS_MAGIC_BYTES) + private_password.encode())

        logging.debug(part1.digest()[:32] + part2.digest()[:32])

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

            response = self.pool_manager.request('GET', uri, headers={'User-Agent': 'TeleHeater',
                                                                      'Content-type': 'application/json; charset=utf-8'})

            if response.status == HTTPStatus.OK:
                response_json = self.decrypt_response_data(response.data)
                if response_json['type'] == 'refEnum':
                    for reference in response_json['references']:
                        result = self.query(reference['uri'])
                    return
                else:
                    result = self.get_prometheus_metric(response_json)
                    if result:
                        results.append(result)
                    return result

            else:
                logging.warning(
                    f"'{uri}' request was not successfull: {response.status} {HTTPStatus(response.status).phrase}")

        except Exception:
            logging.exception(f"'{uri}' error while processing")

    def get_prometheus_metric(self, json):
        metric_name = f"{json['id'].replace('/', '_')}"

        if json['type'] == 'stringValue':

            if 'allowedValues' in json and json['allowedValues'] in [["off", "on"], ["false", "true"],
                                                                     ["INACTIVE", "ACTIVE"], ["stop", "start"]]:

                return dict(type="state",
                            metric=metric_name,
                            value=1.0 if json['value'].lower() in ['on', 'true', 'active', 'start'] else 0.0
                            )

            else:

                return dict(type="info",
                            metric=metric_name,
                            value=json['value'],
                            )

        elif json['type'] == 'floatValue':

            return dict(type=json['unitOfMeasure'],
                        metric=metric_name,
                        value=json['value']
                        )

        else:
            logging.warning(f"Unhandled data type: {json}")


if __name__ == '__main__':

    logging.basicConfig(level=loglevel)

    print(f'Server exporter_port starts...')

    start_http_server(int(exporter_port))

    REGISTRY.register(KM200Crawler(km200_host, km200_gateway_password, km200_private_password))

    while True:
        time.sleep(1)
