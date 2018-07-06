Configuration
=============

All configuration is performed via setting environmental variables.

- Required variables
    - ``IPSEITY_MONGO_HOST``: The IP address or hostname of the mongo server for authentication data
    - ``IPSEITY_PUBLIC_KEY``: A public rsa key in ssh format
    - ``IPSEITY_PRIVATE_KEY``: A private rsa key in ssh format
- Optional variables
    - ``IPSEITY_MONGO_PORT`` (27017): The port the Mongo server is running on
    - ``IPSEITY_MONGO_DB`` (ipseity): The mongo db name to use to store the collection
    - ``IPSEITY_MONGO_COLLECTION`` (authentication): The mongo collection which stores credentials
    - ``IPSEITY_ACCESS_EXP_DELTA`` (72000): A length of time for access tokens to remain valid, in seconds
    - ``IPSEITY_REFRESH_EXP_DELTA`` (2592000): A length of time for refresh tokens to remain valid, in seconds
    - ``IPSEITY_VERBOSITY`` (WARN): The verbosity of the logs
