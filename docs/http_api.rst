HTTP API
========

Quick Reference
---------------

.. qrefflask:: ipseity:app
    :undoc-static:

Authentication
--------------
Authentication is provided to this API via supplying a JWT.

This JWT can be provided in one of the following ways:

- Via the header, in the ``Authorization`` key
- As a form encoded argument as the value associated with the key ``access_token``
- In the query string as the value associated with the key ``access_token``

Each endpoint below specifies one of the following authentication requirements

- **No Authentication**: No authentication is required.
- **Authentication Optional**: Authentication may be provided - the endpoint may 
  perform differently when authentication is provided.
- **Authentication Required**: Authentication must be provided for the endpoint
  to function
- **Password Authentication Required**: Authentication must be provided, and
  the provided token must have been generated in response to a username/password
  based login, rather than a refresh token based login.


Providing Arguments
-------------------

All endpoints of this API utilize a 
:class:`flask_restful.reqparse.RequestParser`
instance to obtain arguments. Thus, values may be provided via any method
which populates either :attr:`flask.Request.json` or :attr:`flask.Request.values` with
the appropriate key.

The following documentation documents these keys and values as if they are provided
via the JSON body of a request.


Endpoint Documentation
----------------------

.. autoflask:: ipseity:app
    :endpoints:
    :undoc-static:
