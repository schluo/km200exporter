# Buderus/Bosch KM200 Exporter for Prometheus
Python based Prometheus Exporter

Can be used as Python Code or as Docker Container. 

Creation of Docker Container:

      docker build --tag km200exporter .

Starting of Docker Container with docker-compose

      docker-compose up -d

Credential, Ports and Polling Interval are given by environmental variables (see also the docker-compose.yml file)

    km200_gateway_password=gateway_password
    km200_private_password=password
    km200_host=<IP>
    exporter_port=9202
    loglevel=WARNING

A Grafana Dashboard example is also provided as JSON template