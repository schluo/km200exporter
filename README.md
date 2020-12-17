# km200prometheus

Python crwaler for a Buderus Heating System Web KM200 endpoint.
When the crawler is called, all known APIs are called recursively and the obtained information is made available as prometheus metric.

The heating system can be controlled via the Buderus website <https://www.buderus-connect.de> or by the [Buderus MyDevice](https://play.google.com/store/apps/details?id=com.bosch.tt.buderus) app from your mobile phone.

## requirements

- Because of the use of string literals Python >= 3.6 is required
- The crawler needs a password you first have to set via the mobile phone app.

## example

    
    docker run -ti -p 9202:9202 -e km200_gateway_password= -e km200_private_password= -e km200_host=192.168.68.125 -e exporter_port=9202  km200exporter:latest

## changelog

### [0.0.2] - 2020-01-04

#### Added

- pip requirements.txt

### [0.0.1] - 2020-01-04

#### Added

- Functionalitiy to provide buderus heating system data as prometheus metric
