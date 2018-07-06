Quick Start
===========

To see a working client server demo:

```
$ docker-compose up -d
$ firefox http://localhost:5000
```

To spin up a freestanding instance (for development) set the
required environmental variables appropriately and:

```
$ ./debug.sh
```

To start a dockerized instance:

```
$ docker build . -t ipseity
$ docker run -p 5000:80 ipseity --name my_ipseity
```
