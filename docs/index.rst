.. ipseity documentation master file, created by
   sphinx-quickstart on Wed Jul  4 19:24:38 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ipseity's documentation!
===================================

**ipseity** (noun): selfhood; individual identity, individuality

An authentication API microservice.

This microservice utilizes `JWTs <https://jwt.io/>`_ to provide authentication assurances to other services. Services may either use this API, or a locally cached copy of the services public key, in order to validate JWTs containing a users name, as well as some minimal subsidiary information.

Passwords are salted/hashed via `bcrypt <https://pypi.org/project/bcrypt/>`_.

Token creation and validation is handled via `PyJWT <https://pypi.org/project/PyJWT/>`_.

Ipseity heavily leverages `flask_jwtlib <http://flask-jwtlib.readthedocs.io>`_ behind the scenes.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   usage
   http_api
   config
   quickstart
   warnings



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
