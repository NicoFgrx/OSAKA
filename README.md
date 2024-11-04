![OSAKA](./logo.jpeg)

# OSAKA
Outil de Sécurité des Architectures Kubernetes Avancées
Advanced Kubernetes Architecture Security Tool

This tool allows to perform the reconstruction of complex attack paths by graph generation in a Kubernetes cluster. It uses Neo4j for the
storage of objects and relationships in database as well as neodash for visualization. The language Cypher
as MySQL allows queries to the database to retrieve graphs.
It can be used by security auditors to quickly identify attack paths  or security experts to monitor theses paths.

There are four microservices within the tool :
- osaka-database
- osaka-loader
- osaka-visualizer
- osaka-editor

The tool was not designed in a secure development model, it is necessary to deploy it in an isolated and controlled environment. Also, it is recommended to install a HTTPS reverse proxy in front of the application.

## Prerequisites :
- Docker
- Docker Compose

## Installation
Configure the environment variables in the. env file at project root but also at sources/. env :
*HOST_IP* is the host system IP address
*NEO4J_PASSWORD* is the database password

### Build and run
```sh
$ cd osaka/build
$ chmod +x build.sh
$ ./build.sh
```
### To stop the services :
```sh
$ cd osaka
$ docker compose down
```
### To start the services :
```sh
$ cd osaka
$ docker compose up -d
```

## Usage 
### Data collection
Run the collect.sh script in the "tools" directory with a kubectl binary and an access to kube-apiserver, then retrieve the "collect-*. zip" and upload the file to the osaka-loader service on port 8080
```sh
$ ./collect.sh 
```
### Reading attack paths
The osaka-visualizer service allows to consult the dashboard in read-only mode. An access to the service can be provided to the beneficiary during an audit (::8082) 

### Customizing graphs
It is necessary to configure the osaka-editor service with the value of *NEO4J_PASSWORD* located in the .env. This gives write access to the dashboard and allows the modification of cypher queries, etc... (::8081)
