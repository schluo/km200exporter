# set base image (host OS)
FROM python

ENV km200_host=localhost
ENV km200_gateway_password=123
ENV km200_private_password=456
ENV exporter_port=9201
ENV loglevel=ERROR

# set the working directory in the container
WORKDIR /code

# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip install -r requirements.txt

# copy the content of the local src directory to the working directory
COPY prometheus_crawler.py/ .

# command to run on container start
CMD [ "python", "./prometheus_crawler.py" , "--km200_gateway_password=${km200_gateway_password}", "--km200_private_password=${km200_private_password}", "--km200_host=${km200_host}", "--exporter_port=${exporter_port}" ]