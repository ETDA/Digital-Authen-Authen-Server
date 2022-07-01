# Authen Server


## Configuration

appsettings.json

## Configuration Path

./appsettings.json

## Installation

$ docker build -t [repository]:[tag] .

$ docker run -d -p 80:80 [repository]:[tag] //http:

$ docker run -d -p 443:443 [repository]:[tag] //https:

## Logs

$ docker ps //To check container ID

$ docker logs [container ID]