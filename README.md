# SecretStroll

## Introduction

In this project, we developed a location-based application, SecretStroll,
that enables users to search for nearby points of interest (POI).

## Files in this repository

This repository contains the skeleton code for Parts 1 and 3:

* `credential.py`—Contains the signature scheme and ABC implementation.
* `credential_utils.py`—Contains utility methods used in the implementation of the signature scheme and the ABCs.
* `stroll.py`—Contains the implementation of the client and server code related to the ABCs.
* `stroll_utils.py`—Contains utility methods used in `stroll.py`.
* `client.py`—Client CLI calling classes and methods defined in `stroll.py`.
* `server.py`—Server CLI calling classes and methods defined in `stroll.py`.
* `serialization.py`—Extends the library `jsonpickle` to serialize python
  objects.
* `serialization_utils.py`—Contains utility methods for the serialization.
* `fingerprinting.py`—Contains ML implementation for the fingerprinting attack.
* `requirements.txt`—Required Python libraries.
* `docker-compose.yaml`—*docker compose* configuration describing how to run the
  Docker containers.
* `docker/`—Directory containing Docker configurations for running the client
  and the server.
* `tor/`—Intentionally empty folder needed to run a Tor server.
* `fingerprint.db`—Database containing POI information for Part 3.
* `evaluation_stroll.py`—Test for evaluation of the performance of the ABCs.
* `test_*`-Files containing unit tests for the respective implementation files.
* `zkp_utils.py`-Contains implementation of the zero knowledge proofs.
* `capture.sh`-Shell script for capturing the request traces used for feature extraction.
* `feature_extraction.ipynb`-Contains the feature extraction code and writes the extracted feature to file.
The generated file is later used in `fingerprinting.py`.
* `privacy_evaluation.ipynb`-Contains the deanonymization attack and defence code.

## Server and client deployment

The server and client code deployment is handled by Docker.

### Working with the Docker infrastructure

*Before launching the infrastructure, ensure the `tor` directory in the project's
directory has the correct permissions.*
```
student@cs523:~$ cd cs523/secretstroll/
student@cs523:~/cs523/secretstroll$ chmod 777 tor
student@cs523:~/cs523/secretstroll$ ls -ld tor
drwxrwxrwx 2 student student    4096 mar 24 15:31 tor
```

The server and the client run in a Docker infrastructure composed of 2
containers, and a virtual network.

Before setting up the Docker infrastructure for the first time, you must first
build the images which will be used to run the client and server containers. To
do so, run the following command in the directory which contains the
file `docker-compose.yml`:
```
docker compose build
```

To set up the Docker infrastructure, run the following command in the directory
containing the file `docker-compose.yml`:
```
docker compose up -d
```

When you stop working with the infrastructure, remember to shut it down by
running the following command in the `secretstroll` directory containing the file
`docker-compose.yml`:
```
docker compose down
```

**Note:** *If you forget to shut down the Docker infrastructure, e.g., before
shutting down your computer, you might end up with stopped Docker containers
preventing the creation of the new ones when you to re-launch the infrastructure
the next time. This can be fixed by removing the network bridge with
`docker compose down` and destroying the stopped Docker containers with
`docker container prune -f`.*

### Tor integration

Integrating Tor into the project should be seamless. The Docker configuration
is designed to run Tor in the background, and the code is designed
to use the Tor if requested with no additional effort.

If your project works if used normally, but fails when using Tor, you can check
if its log file in the Docker container gives a clue to what is happening:

```
cat /var/log/service/tor/current
```

### Server

It is easier to run the commands in a Docker container by opening a shell, and
then running the commands inside this shell.

To execute a shell in the container in which the server is to be launched, run
the following command:

```
docker exec -it cs523-server /bin/bash
```

In this container, the root directory of the project is mounted on `/server`.
```
cd /server
```

The server has two subcommands: `gen-ca` and `run`. `gen-ca` generates
the public and secret keys, and `run` runs the server. The server and its
subcommands have a help option, which you can access using the `-h` argument.

Key generation example:
```
python3 server.py setup -S restaurant -S bar -S sushi

usage: server.py setup [-h] [-p PUB] [-s SEC] -S SUBSCRIPTIONS

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file in which to write the public key.
                        (default: key.pub)
  -s SEC, --sec SEC     Name of the file in which to write the secret key.
                        (default: key.sec)
  -S SUBSCRIPTIONS, --subscriptions SUBSCRIPTIONS
                        Subscriptions recognized by the server.
```

Server run example:
```
python3 server.py run

usage: server.py run [-h] [-D DATABASE] [-p PUB] [-s SEC]

optional arguments:
  -h, --help            show this help message and exit
  -D DATABASE, --database DATABASE
                        Path to the PoI database.
  -p PUB, --pub PUB     Name of the file containing the public key.
  -s SEC, --sec SEC     Name of the file containing the secret key.
```

In the Part 3 of the project, the server is expected to be accessible as a Tor
hidden service. The server's Docker container configures Tor to create a hidden
service and redirects the traffic to the Python server. The server serves local
and hidden service requests simultaneously by default.

### Client

To execute a shell in the client container, run the following command:

```
docker exec -it cs523-client /bin/bash
```

In this container, the root directory of the project is mounted on `/client`.
```
cd /client
```

The client has four subcommands: `get-pk`, `register`, `loc`, and `grid`. As for
the server, the client and its subcommands have a help option, which you can
access using the `-h` argument.

Use `get-pk` to retrieve the public key from the server:
```
python3 client.py get-pk

usage: client.py get-pk [-h] [-o OUT] [-t]

optional arguments:
  -h, --help         show this help message and exit
  -o OUT, --out OUT  Name of the file in which to write the public key.
                     (default: key-client.pub)
  -t, --tor          Use Tor to connect to the server.
```

Use `register` to register an account on the serve:
```
python3 client.py register -u your_name -S restaurant -S bar

usage: client.py register [-h] [-p PUB] -u USER [-o OUT] -S SUBSCRIPTIONS [-t]

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file from which to read the public key.
                        (default: key-client.pub)
  -u USER, --user USER  User name.
  -o OUT, --out OUT     Name of the file in which to write the attribute-based
                        credential. (default: anon.cred)
  -S SUBSCRIPTIONS, --subscriptions SUBSCRIPTIONS
                        Subscriptions to register.
  -t, --tor             Use Tor to connect to the server.
```

Use `loc` and `grid` commands to retrieve information about points of interests
using lat/lon location and cell identifier, respectively:
```
python3 client.py loc 46.52345 6.57890 -T restaurant -T bar

usage: client.py loc [-h] [-p PUB] [-c CREDENTIAL] -T TYPES [-t] lat lon

positional arguments:
  lat                   Latitude.
  lon                   Longitude.

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file from which to read the public key.
                        (default: key-client.pub)
  -c CREDENTIAL, --credential CREDENTIAL
                        Name of the file from which to read the attribute-
                        based credential. (default: anon.cred)
  -T TYPES, --types TYPES
                        Types of services to request.
  -t, --tor             Use Tor to connect to the server.
```

**Warning**: The database only contains points of interest with latitude in
range \[46.5, 46.57\] and longitude in range \[6.55, 6.65\] (Lausanne area).
You can make queries outside these values, but you will not find anything
interesting.

```
python3 client.py grid 42 -T restaurant

usage: client.py grid [-h] [-p PUB] [-c CREDENTIAL] [-T TYPES] [-t] cell_id

positional arguments:
  cell_id               Cell identifier.

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file from which to read the public key.
                        (default: key-client.pub)
  -c CREDENTIAL, --credential CREDENTIAL
                        Name of the file from which to read the attribute-
                        based credential. (default: anon.cred)
  -T TYPES, --types TYPES
                        Types of services to request.
  -t, --tor             Use Tor to connect to the server.
```

## A sample run of Part 1
Here we show a typical run of the system for Part 1.

Initialization:


Open a shell
```
$ cd cs523/secretstroll
$ docker compose build
$ docker compose up -d
```

Server side:

Open a shell
```
$ cd cs523/secretstroll
$ docker exec -it cs523-server /bin/bash
(server) $ cd /server
(server) $ python3 server.py setup -s key.sec -p key.pub -S restaurant -S bar -S dojo
(server) $ python3 server.py run -D fingerprint.db -s key.sec -p key.pub
```

Client side:
```
Open a shell
$ cd cs523/secretstroll
$ docker exec -it cs523-client /bin/bash
(client) $ cd /client
(client) $ python3 client.py get-pk
(client) $ python3 client.py register -u your_name -S restaurant -S bar -S dojo
(client) $ python3 client.py loc 46.52345 6.57890 -T restaurant -T bar
```

Close everything down at the end of the experiment:
```
$ docker compose down
```

## A sample run of Part 3
Here we provide a typical run of the system for Part 3:

Initialization:

```
Open a shell
$ cd cs523/secretstroll
$ docker compose build
$ docker compose up -d
```

Server side:

You should have already generated the keys in Part 1, so you do not need to
repeat that step.

```
Open a shell
$ cd cs523/secretstroll
$ docker exec -it cs523-server /bin/bash
(server) $ cd /server
(server) $ python3 server.py run
```

Client side:

You should have already performed the registration in Part 1, so you do not need
to the repeat the step. Use the grid parameter to query for a particular cell.
Set the reveal argument (-r) to an empty value. Set the -t argument to use Tor. The example run below queries the server for cell ID = 42.

```
Open a shell
$ cd cs523/secretstroll
$ docker exec -it cs523-client /bin/bash
(client) $ cd /client
(client) $ python3 client.py grid 42 -T restaurant -t
```

Close everything down at the end of the experiment:
```
$ docker compose down
```
