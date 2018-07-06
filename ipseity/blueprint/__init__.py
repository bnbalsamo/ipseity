"""
ipseity - an authentication microservice
"""
import logging
import datetime
from functools import wraps
from uuid import uuid4

from flask import Blueprint, Response, abort, g
from flask_restful import Resource, Api, reqparse

import jwt
import bcrypt

from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

import flask_jwtlib

from .exceptions import UserAlreadyExistsError, \
    UserDoesNotExistError, IncorrectPasswordError, InvalidTokenError, \
    TokenTypeError, UserDeactivatedError


__author__ = "Brian Balsamo"
__email__ = "brian@brianbalsamo.com"
__version__ = "0.5.0"


BLUEPRINT = Blueprint('ipseity', __name__)

BLUEPRINT.config = {}

API = Api(BLUEPRINT)

log = logging.getLogger(__name__)


# Register some callbacks that implement
# API specific functionality in the library

# Tokens aren't valid just from being signed/well-formed
# they also have to be of type "access_token"
def check_token(token):
    x = flask_jwtlib._DEFAULT_CHECK_TOKEN(token)
    if x:
        json_token = jwt.decode(
            token.encode(),
            BLUEPRINT.config['VERIFY_KEY'],
            algorithm=BLUEPRINT.config['ALGO']
        )
        if json_token['token_type'] == 'access_token':
            return True
    return False


flask_jwtlib.check_token = check_token


# Decorator for functions that require using a token
# which was generated from username/password authentication,
# rather than refresh token.
# Only call this _after_ flask_jwtlib.requires_authentication
def requires_password_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.json_token['authentication_method'] != 'password':
            abort(403)
        return f(*args, **kwargs)
    return decorated


# So that we don't store tokens forever
def prune_disallowed_tokens(user):
    log.debug("Pruning disallowed tokens for {}".format(user))
    user_db_doc = BLUEPRINT.config['authentication_coll'].find_one(
        {"user": user}
    )
    for x in user_db_doc['disallowed_tokens']:
        try:
            token = jwt.decode(
                x.encode(),
                BLUEPRINT.config['VERIFY_KEY'],
                algorithm=BLUEPRINT.config['ALGO']
            )
            if token['token_type'] != 'refresh_token':
                raise TokenTypeError
        except (jwt.InvalidTokenError, TokenTypeError):
            BLUEPRINT.config['authentication_coll'].update_one(
                {'user': user_db_doc['user']},
                {"$pull": {"disallowed_tokens": x}}
            )


class Version(Resource):
    def get(self):
        """
        .. :quickref: Version; Return the version number of the API

        **Authentication**: No Authentication

        Return the version number of the API

        :>json string version: The version number of the API

        :statuscode 200: No error
        """
        return {"version": __version__}


class PublicKey(Resource):
    def get(self):
        """
        .. :quickref: Public Key; Returns the public key, if applicable

        **Authentication**: No Authentication

        Returns the public key as plaintext, if applicable.

        :statuscode 200: No error
        :statuscode 404: A symmetric algorithm is in use, there is no
            public key
        """
        if BLUEPRINT.config['VERIFY_KEY'] == BLUEPRINT.config['SIGNING_KEY']:
            abort(404)
        return Response(BLUEPRINT.config['VERIFY_KEY'])


class User(Resource):
    @flask_jwtlib.optional_authentication
    def get(self):
        """
        .. :quickref: User; If authentication provided get token JSON payload

        **Authentication**: Authentication Optional

        If authentication is provided return the token's JSON payload, otherwise
        returns an empty response with status code 204.

        :Response JSON Object: The token payload
        :statuscode 200: No error
        :statuscode 204: No valid token found
        """
        if flask_jwtlib.is_authenticated():
            return g.json_token
        else:
            return Response(status=204)

    def post(self):
        """
        .. :quickref: User; Create a new user

        **Authentication**: No Authentication

        Create a new user

        :<json str user: The username of the user to create
        :<json str pass: The password for the new user

        :statuscode 201: No error
        :statuscode 403: User already exists
        """
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, required=True)
        parser.add_argument('pass', type=str, required=True)
        args = parser.parse_args()

        log.debug("Attempting to create user {}".format(args['user']))
        try:
            BLUEPRINT.config['authentication_coll'].insert_one(
                {
                    'user': args['user'],
                    'uid': uuid4().hex,
                    'password': bcrypt.hashpw(args['pass'].encode(), bcrypt.gensalt()),
                    'disallowed_tokens': [],
                    'active': True
                }
            )
        except DuplicateKeyError:
            raise UserAlreadyExistsError(args['user'])

        log.info("User {} created".format(args['user']))

        return Response(status=201)

    @flask_jwtlib.requires_authentication
    @requires_password_authentication
    def delete(self):
        """
        .. :quickref: User; Delete a user

        **Authentication**: Password Authentication Required

        Delete the user

        :statuscode 204: No error
        :statuscode 404: User doesn't exist, or delete failed
        """
        log.debug("Attempting to delete user: {}".format(g.json_token['user']))

        res = BLUEPRINT.config['authentication_coll'].update_one(
            {'user': g.json_token['user']},
            {'$set': {'active': False}}
        )

        if res.modified_count == 1:
            # success
            log.info("User {} deleted".format(g.json_token['user']))
            return Response(status=204)
        else:
            # fail
            log.info("Deletetion attempt on user {} failed".format(g.json_token['user']))
            abort(404)

    @flask_jwtlib.requires_authentication
    @requires_password_authentication
    def patch(self):
        """
        .. :quickref: User; Changes a users password

        **Authentication**: Password Authentication Required

        Changes the authenticated users password.

        :<json str pass: The string to change the password to

        :statuscode 200: No error
        """
        parser = reqparse.RequestParser()
        parser.add_argument('pass', type=str, required=True)
        args = parser.parse_args()

        BLUEPRINT.config['authentication_coll'].update_one(
            {'user': g.json_token['user']},
            {'$set': {'password': bcrypt.hashpw(args['pass'].encode(), bcrypt.gensalt())}}
        )

        return Response(status=200)


class Token(Resource):
    def get(self):
        """
        .. :quickref: Token; get a token

        **Authentication**: No Authentication

        Get a token

        Returns an encoded token in plaintext

        :<json str user: The username to authenticate as, or an encoded refresh token
        :<json str pass: The password for the user, if not utilizing a refresh token

        :statuscode 200: No error
        :statuscode 400: Refresh token is invalid
        :statuscode 404: User login error
        :statuscode 403: Account deleted
        """
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, required=True)
        parser.add_argument('pass', type=str, default=None)
        args = parser.parse_args()
        log.debug("Attempting to auth {}".format(args['user']))

        auth_method = None
        if not args['pass']:
            # Token based auth
            auth_method = "refresh_token"
            try:
                token = jwt.decode(
                    args['user'].encode(),
                    BLUEPRINT.config['VERIFY_KEY'],
                    algorithm=BLUEPRINT.config['ALGO']
                )
                log.debug("Valid token provided: {}".format(args['user']))
            except jwt.InvalidTokenError:
                log.debug("Invalid token provided: {}".format(args['user']))
                raise InvalidTokenError
            if token['token_type'] != 'refresh_token':
                raise TokenTypeError("Not a refresh token")
            user = BLUEPRINT.config['authentication_coll'].find_one(
                {"user": token['user']}
            )
            # For the case where someone has a valid refresh token, but the
            # account has since been deleted
            if user is None:
                raise UserDoesNotExistError(token['user'])
            if token['uid'] != user['uid']:
                # This is a valid token, but the account has been deleted
                # since it was created, so it could be a new user. This
                # token can't work anymore
                raise InvalidTokenError(token['user'])
            if args['user'] in user['disallowed_tokens']:
                log.debug("Refresh token {} disallowed".format(args['user']))
                raise InvalidTokenError(args['user'])
        else:
            # username/password auth
            auth_method = "password"
            user = BLUEPRINT.config['authentication_coll'].find_one(
                {'user': args['user']}
            )
            if not user:
                log.debug("Username {} does not exist".format(args['user']))
                raise UserDoesNotExistError(args['user'])
            if not bcrypt.checkpw(args['pass'].encode(), user['password']):
                log.debug("Incorrect password provided for username {}".format(args['user']))
                raise IncorrectPasswordError(args['user'])

        # Prune the users disallowed tokens, so no invalid tokens
        # or old tokens stick in the DB
        prune_disallowed_tokens(user['user'])

        if not user['active']:
            raise UserDeactivatedError(user['user'])
        # If we got to here we found a user, either by refresh token or
        # username/password auth
        log.debug("Assembling token for {}".format(args['user']))
        token = {
            'user': user['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(
                seconds=BLUEPRINT.config.get('ACCESS_EXP_DELTA', 72000)  # 20 hours
            ),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow(),
            'authentication_method': auth_method,
            'token_type': 'access_token'
        }

        encoded_token = jwt.encode(
            token,
            BLUEPRINT.config['SIGNING_KEY'],
            algorithm=BLUEPRINT.config['ALGO']
        )
        log.debug("User {} successfully authenticated".format(args['user']))
        return Response(encoded_token.decode())


class CheckToken(Resource):
    def get(self):
        """
        .. :quickref: Validates a token

        **Authentication**: No Authentication

        Validates a token

        If the token is valid, returns the token's JSON payload

        :<json str access_token: The token to check

        :Response JSON Object: The token payload

        :statuscode 200: No error
        :statuscode 400: Token is invalid
        """
        parser = reqparse.RequestParser()
        parser.add_argument('access_token', type=str, required=True)
        args = parser.parse_args()

        log.debug("Checking token: {}".format(args['access_token']))

        try:
            token = jwt.decode(
                args['access_token'].encode(),
                BLUEPRINT.config['VERIFY_KEY'],
                algorithm=BLUEPRINT.config['ALGO']
            )
            if token['token_type'] != "access_token":
                raise TokenTypeError
            log.debug("Valid token provided: {}".format(args['access_token']))
            return token
        except (jwt.InvalidTokenError, TokenTypeError):
            log.debug("Invalid token provided: {}".format(args['access_token']))
            raise InvalidTokenError


class RefreshToken(Resource):
    @flask_jwtlib.requires_authentication
    @requires_password_authentication
    def get(self):
        """
        .. :quickref: Refresh Token; get a refresh token

        Get a refresh token

        Returns an encoded token in plaintext

        **Authentication**: Password Authentication Required

        :statuscode 200: No error
        """
        # we need their uid for the fresh token
        user_db_doc = BLUEPRINT.config['authentication_coll'].find_one(
            {"user": g.json_token['user']}
        )
        if user_db_doc is None:
            # I don't think this is possible, but it never hurts to be sure.
            abort(500)
        token = {
            'user': g.json_token['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(
                seconds=BLUEPRINT.config.get('REFRESH_EXP_DELTA', 2592000)  # a month
            ),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow(),
            'token_type': 'refresh_token',
            'uid': user_db_doc['uid']
        }
        encoded_token = jwt.encode(
            token,
            BLUEPRINT.config['SIGNING_KEY'],
            algorithm=BLUEPRINT.config['ALGO']
        )
        prune_disallowed_tokens(g.json_token['user'])
        return Response(encoded_token)

    @flask_jwtlib.requires_authentication
    def delete(self):
        """
        .. :quickref: Refresh Token; delete a refresh token

        Delete a refresh token

        **Authentication**: Authentication Required

        :statuscode 204: No error
        """
        parser = reqparse.RequestParser()
        parser.add_argument('refresh_token', type=str, required=True)
        args = parser.parse_args()

        try:
            token = jwt.decode(
                args['refresh_token'].encode(),
                BLUEPRINT.config['VERIFY_KEY'],
                algorithm=BLUEPRINT.config['ALGO']
            )
        except jwt.InvalidTokenError:
            raise InvalidTokenError()
        if token['token_type'] != 'refresh_token' or \
                token['user'] != g.json_token['user']:
            raise TokenTypeError

        res = BLUEPRINT.config['authentication_coll'].update_one(
            {'user': g.json_token['user']},
            {'$push': {'disallowed_tokens': args['refresh_token']}}
        )

        if res.modified_count > 0:
            prune_disallowed_tokens(g.json_token['user'])
            return Response(status=204)
        else:
            abort(404)


@BLUEPRINT.record
def handle_configs(setup_state):
    app = setup_state.app
    BLUEPRINT.config.update(app.config)
    if BLUEPRINT.config.get('DEFER_CONFIG'):
        log.debug("DEFER_CONFIG set, skipping configuration")
        return

    authentication_client = MongoClient(
        BLUEPRINT.config['MONGO_HOST'],
        int(BLUEPRINT.config.get('MONGO_PORT', 27017))
    )
    authentication_db = \
        authentication_client[BLUEPRINT.config.get('MONGO_DB', 'ipseity')]

    BLUEPRINT.config['authentication_coll'] = \
        authentication_db[BLUEPRINT.config.get("MONGO_COLLECTION", 'authentication')]

    BLUEPRINT.config['authentication_coll'].create_index(
        [('user', ASCENDING)],
        unique=True
    )

    if BLUEPRINT.config['ALGO'] not in jwt.algorithms.get_default_algorithms():
        raise RuntimeError(
            "Unsupported algorithm, select one of: {}".format(
                ", ".join(x for x in jwt.algorithms.get_default_algorithms().keys())
            )
        )

    asymmetric_algos = [
        'PS256',
        'PS384',
        'PS512',
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512'
    ]

    if BLUEPRINT.config['ALGO'] in asymmetric_algos:
        if BLUEPRINT.config.get("PRIVATE_KEY") is None or \
                BLUEPRINT.config.get("PUBLIC_KEY") is None:
            raise RuntimeError(
                "Asymmetric algos must specify both IPSEITY_PRIVATE_KEY " +
                "and IPSEITY_PUBLIC_KEY"
            )
        BLUEPRINT.config['SIGNING_KEY'] = BLUEPRINT.config['PRIVATE_KEY']
        BLUEPRINT.config['VERIFY_KEY'] = BLUEPRINT.config['PUBLIC_KEY']
        flask_jwtlib.set_permanent_verification_key(BLUEPRINT.config['PUBLIC_KEY'])
    else:
        if BLUEPRINT.config.get("PRIVATE_KEY") is None or \
                BLUEPRINT.config.get("PUBLIC_KEY") is not None:
            raise RuntimeError(
                "Symmetric algos must specify IPSEITY_PRIVATE_KEY " +
                "and NOT specify IPSEITY_PUBLIC_KEY"
            )
        BLUEPRINT.config['SIGNING_KEY'] = BLUEPRINT.config['PRIVATE_KEY']
        BLUEPRINT.config['VERIFY_KEY'] = BLUEPRINT.config['PRIVATE_KEY']
        flask_jwtlib.set_permanent_verification_key(BLUEPRINT.config['PRIVATE_KEY'])

    if BLUEPRINT.config.get("VERBOSITY"):
        log.debug("Setting verbosity to {}".format(str(BLUEPRINT.config['VERBOSITY'])))
        logging.basicConfig(level=BLUEPRINT.config['VERBOSITY'])
    else:
        log.debug("No verbosity option set, defaulting to WARN")
        logging.basicConfig(level="WARN")


API.add_resource(User, "/user")
API.add_resource(Token, "/token")
API.add_resource(RefreshToken, "/refresh_token")
API.add_resource(CheckToken, "/check")
API.add_resource(PublicKey, "/pubkey")
API.add_resource(Version, "/version")
