Usage
=====

This microservice utilizes JWTs to provide authentication assurances to other services. Services may either use this API, or a locally cached copy of the services public key, in order to validate JWTs containing a users name, as well as some minimal subsidiary information.
