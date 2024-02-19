import getpass
import os
import traceback
from functools import wraps
from threading import Lock
from typing import Dict
import sys
import pytz
from tzlocal import get_localzone
from xhtml2pdf import pisa

from aw_core.launch_start import create_shortcut, delete_shortcut, launch_app, delete_launch_app, \
    check_startup_status
from aw_core.util import authenticate, is_internet_connected, reset_user
import pandas as pd
from datetime import datetime, timedelta, date, time
import iso8601
from aw_core import schema, db_cache
from aw_core.models import Event
from aw_core.cache import *
from aw_query.exceptions import QueryException
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    request,
)
from flask_restx import Api, Resource, fields
import jwt
from io import BytesIO
from . import logger
from .api import ServerAPI
from .exceptions import BadRequest, Unauthorized
from aw_qt.manager import Manager

application_cache_key = "application_cache"
manager = Manager()


def host_header_check(f):
    """
        Check if token is valid. This is a decorator for API methods that need to be decorated in order to check the token in the Host header

        @param f - function to be decorated with this

        @return tuple of ( token error
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        """
         Decorate to check token. This is a decorator that can be used as a context manager or in a class decorator.


         @return tuple of JSON response and status code. If status code is 0 it means success
        """
        excluded_paths = [
            '/api/0/buckets/',
            '/api/swagger.json', '/api/0/ralvie/login',
            '/api/0/login', '/api/0/user'
        ]
        # This method is used to check if the request is valid and if the request is a heartbeat credentials and the request is not a valid credentials.
        if "/heartbeat" not in request.path and "/credentials" not in request.path and request.path not in excluded_paths and request.method != 'OPTIONS':
            token = request.headers.get("Authorization")
            # This method is used to validate the token.
            if not token:
                logging.warning("Token is missing")
                return {"message": "Token is missing"}, 401
            elif "/company" not in request.path:
                cache_key = "sundial"
                cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
                user_key = cached_credentials.get("user_key")
                try:
                    jwt.decode(token.replace("Bearer ", ""), key=user_key, algorithms=["HS256"])
                except jwt.InvalidTokenError as e:
                    logging.error("Invalid token")
                    return {"message": "Invalid token"}, 401

        server_host = current_app.config["HOST"]
        req_host = request.headers.get("host", None)
        # Check if server is listening on 0. 0. 0. 0. 0. 0 host header check is disabled.
        if server_host == "0.0.0.0":
            logging.warning(
                "Server is listening on 0.0.0.0, host header check is disabled (potential security issue)."
            )
        elif req_host is None:
            return {"message": "host header is missing"}, 400
        elif req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
            return {"message": f"host header is invalid (was {req_host})"}, 400

        return f(*args, **kwargs)

    return decorator


authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
    }
}
blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/", decorators=[host_header_check], authorizations=authorizations)

# Loads event and bucket schema from JSONSchema in aw_core
event = api.schema_model("Event", schema.get_json_schema("event"))
bucket = api.schema_model("Bucket", schema.get_json_schema("bucket"))
buckets_export = api.schema_model("Export", schema.get_json_schema("export"))

# TODO: Construct all the models from JSONSchema?
#       A downside to contructing from JSONSchema: flask-restplus does not have marshalling support

info = api.model(
    "Info",
    {
        "hostname": fields.String(),
        "version": fields.String(),
        "testing": fields.Boolean(),
        "device_id": fields.String(),
    },
)

create_bucket = api.model(
    "CreateBucket",
    {
        "client": fields.String(required=True),
        "type": fields.String(required=True),
        "hostname": fields.String(required=True),
    },
)

update_bucket = api.model(
    "UpdateBucket",
    {
        "client": fields.String(required=False),
        "type": fields.String(required=False),
        "hostname": fields.String(required=False),
        "data": fields.String(required=False),
    },
)

query = api.model(
    "Query",
    {
        "timeperiods": fields.List(
            fields.String, required=True, description="List of periods to query"
        ),
        "query": fields.List(
            fields.String, required=True, description="String list of query statements"
        ),
    },
)


def copy_doc(api_method):
    """
     Copy docstrings from another function to the decorated function. Used to copy docstrings in ServerAPI over to the flask - restplus Resources.

     @param api_method - The method to copy the docstrings from.

     @return A decorator that copies the docstrings from the decorated function
    """
    """Decorator that copies another functions docstring to the decorated function.
    Used to copy the docstrings in ServerAPI over to the flask-restplus Resources.
    (The copied docstrings are then used by flask-restplus/swagger)"""

    def decorator(f):
        """
         Decorate a function to add documentation. This is useful for methods that are decorated with @api_method

         @param f - The function to decorate.

         @return The decorated function as a decorator ( not a decorator
        """
        f.__doc__ = api_method.__doc__
        return f

    return decorator


# SERVER INFO
def format_duration(duration):
    """
     Format duration in human readable format. This is used to format durations when logging to logcat

     @param duration - The duration to format.

     @return A string representing the duration in human readable format e. g
    """
    # Format duration in H m s format.
    if duration is not None:
        seconds = int(duration)
        d = seconds // (3600 * 24)
        h = seconds // 3600 % 24
        m = seconds % 3600 // 60
        s = seconds % 3600 % 60
        # Returns a string representation of the H m s.
        if h > 0:
            return '{:02d}H {:02d}m {:02d}s'.format(h, m, s)
        elif m > 0:
            return '{:02d}m {:02d}s'.format(m, s)
        elif s > 0:
            return '{:02d}s'.format(s)
    return '1s'


@api.route("/0/info")
class InfoResource(Resource):
    @api.doc(security="Bearer")
    @api.marshal_with(info)
    @copy_doc(ServerAPI.get_info)
    def get(self) -> Dict[str, Dict]:
        """
         Get information about the application. This is a shortcut for : meth : ` flask. api. get_info `.


         @return A dictionary of application information or an empty dictionary if there is no information
        """
        return current_app.api.get_info()


# Users


@api.route("/0/user")
class UserResource(Resource):
    @api.doc(security="Bearer")
    def post(self):
        """
         Create a Sundial user. This is a POST request to the / v1 / users endpoint.


         @return a dictionary containing the user's details and a boolean indicating if the user was
        """
        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # If internet connection is not connected to internet and try again.
        if not is_internet_connected():
            print("Please connect to internet and try again.")
        data = request.get_json()
        # Returns a 400 if the user is not a valid email or password
        if not data['email']:
            return {"message": "User name is mandatory"}, 400
        elif not data['password']:
            return {"message": "Password is mandatory"}, 400
        # Returns the user who is currently using the cached credentials.
        if cached_credentials is not None:
            user = cached_credentials.get("encrypted_db_key")
        else:
            user = None
        # Create a user and authorize it
        if True:
            result = current_app.api.create_user(data)
            # This method is used to authorize and create a company.
            if result.status_code == 200 and json.loads(result.text)["code"] == 'UASI0001':
                userPayload = {
                    "userName": data['email'],
                    "password": data['password']
                }
                authResult = current_app.api.authorize(userPayload)

                # Returns the auth result as JSON
                if 'company' not in data:
                    return json.loads(authResult.text), 200

                # This method is used to create a company and create a company
                if authResult.status_code == 200 and json.loads(authResult.text)["code"] == 'RCI0000':
                    token = json.loads(authResult.text)["data"]["access_token"]
                    id = json.loads(authResult.text)["data"]["id"]
                    companyPayload = {
                        "name": data['company'],
                        "code": data['company'],
                        "status": "ACTIVE"
                    }

                    companyResult = current_app.api.create_company(companyPayload, 'Bearer ' + token)

                    # This method is called when the user is created
                    if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
                        current_app.api.get_user_credentials(id, 'Bearer ' + token)
                        init_db = current_app.api.init_db()
                        # This function is called when the user is created
                        if init_db:
                            return {"message": "Account created successfully"}, 200
                        else:
                            reset_user()
                            return {"message": "Something went wrong"}, 500
                    else:
                        return json.loads(companyResult.text), 200
                else:
                    return json.loads(authResult.text), 200
            else:
                return json.loads(result.text), 200
        else:
            return {"message": "User already exist"}, 200


@api.route("/0/company")
class CompanyResource(Resource):
    def post(self):
        """
         Create a company in UASI. This will be used for creating company in UASI.


         @return tuple of ( response status_code ) where response is empty if success or a dict with error
        """
        data = request.get_json()
        token = request.headers.get("Authorization")
        # If token is not set return 401
        if not token:
            return {"message": "Token is required"}, 401
        # Error message if name is not set
        if not data['name']:
            return {"message": "Company name is mandatory"}, 400
        companyPayload = {
            "name": data['name'],
            "code": data['code'],
            "status": "ACTIVE"
        }

        companyResult = current_app.api.create_company(companyPayload, token)

        # Returns the status code of the company result.
        if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
            return json.loads(companyResult.text), 200
        else:
            return json.loads(companyResult.text), companyResult.status_code


# Login by system credentials
@api.route("/0/login")
class LoginResource(Resource):
    def post(self):
        """
         Authenticate and encode user credentials. This is a POST request to / api / v1 / sundial


         @return Response code and JSON
        """
        data = request.get_json()
        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        user_key = cached_credentials.get("user_key")
        print(user_key)
        # Returns a JSON object with the user_key data.
        if user_key:
            # Authenticates the user with the given data.
            if authenticate(data['userName'], data['password']):
                encoded_jwt = jwt.encode({"user": data['userName'], "email": cached_credentials.get("email"),
                                          "phone": cached_credentials.get("phone")}, user_key, algorithm="HS256")
                return {"code": "SDI0000", "message": "Success", "data": {"token": encoded_jwt}}, 200
            else:
                return {"code": "SDE0000", "message": "Username or password is wrong"}, 200
        else:
            return {"message": "User does not exist"}, 200

    def get(self):
        """
         Get method for sundial. json API. This method is used to check if user exist or not.


         @return 200 if user exist 401 if user does not exist
        """
        data = request.get_json()
        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # Returns the encrypted_db_key if the cached credentials are cached.
        if cached_credentials is not None:
            user_key = cached_credentials.get("encrypted_db_key")
        else:
            user_key = None
        # Returns a 200 if user_key is not found 401 if user_key is not present
        if user_key:
            return {"message": "User exist"}, 200
        else:
            return {"message": "User does not exist"}, 401


# Login by ralvie cloud
@api.route("/0/ralvie/login")
class RalvieLoginResource(Resource):
    def post(self):
        """
         Authenticate and log in a user. This is the endpoint for authenticating and log in a user.


         @return A JSON with the result of the authentication and user
        """
        cache_key = "sundial"
        # Check Internet Connectivity
        response_data = {}
        # If the internet is not connected return a 200 error message.
        if not is_internet_connected():
            return jsonify({"message": "Please connect to the internet and try again."}), 200

        # Parse Request Data
        data = request.get_json()
        user_name = data.get('userName')
        password = data.get('password')

        # JSON response with user_name password user_name user_name password
        if not user_name:
            return jsonify({"message": "User name is mandatory"}), 400
        elif not password:
            return jsonify({"message": "Password is mandatory"}), 400

        # Reset User Data
        reset_user()

        # Authenticate User
        auth_result = current_app.api.authorize(data)

        # Returns a JSON response with the user credentials.
        if auth_result.status_code == 200 and json.loads(auth_result.text)["code"] == 'UASI0011':
            # Retrieve Cached User Credentials
            cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")

            # Get the User Key
            user_key = cached_credentials.get("encrypted_db_key") if cached_credentials else None

            # This function is used to get user credentials from the user_key
            if user_key is None:
                token = json.loads(auth_result.text)["data"]["access_token"]
                user_id = json.loads(auth_result.text)["data"]["id"]
                current_app.api.get_user_credentials(user_id, 'Bearer ' + token)
                init_db = current_app.api.init_db()

                # Reset the user to the default user
                if not init_db:
                    reset_user()
                    return {"message": "Something went wrong"}, 500

            # Generate JWT
            payload = {
                "user": getpass.getuser(),
                "email": cache_user_credentials(cache_key, "SD_KEYS").get("email"),
                "phone": cache_user_credentials(cache_key, "SD_KEYS").get("phone")
            }
            encoded_jwt = jwt.encode(payload, cache_user_credentials(cache_key, "SD_KEYS").get("user_key"),
                                     algorithm="HS256")

            # Response
            response_data['code'] = "UASI0011",
            response_data["message"] = json.loads(auth_result.text)["message"],
            response_data["data"]: {"token": "Bearer " + encoded_jwt}
            return {"code": "UASI0011", "message": json.loads(auth_result.text)["message"],
                    "data": {"token": "Bearer " + encoded_jwt}}, 200
        else:
            return {"code": json.loads(auth_result.text)["code"], "message": json.loads(auth_result.text)["message"],
                    "data": json.loads(auth_result.text)["data"]}, 200


# BUCKETS

@api.route("/0/buckets/<string:bucket_id>/formated_events")
class EventsResource(Resource):
    # For some reason this doesn't work with the JSONSchema variant
    # Marshalling doesn't work with JSONSchema events
    # @api.marshal_list_with(event)
    @api.doc(model=event)
    @api.param("limit", "the maximum number of requests to get")
    @api.param("start", "Start date of events")
    @api.param("end", "End date of events")
    @copy_doc(ServerAPI.get_events)
    def get(self, bucket_id):
        """
         Get events for a bucket. This endpoint is used to retrieve events that have been submitted to the API for a given bucket.

         @param bucket_id - the id of the bucket to retrieve events for

         @return a tuple of ( events status
        """
        args = request.args
        limit = int(args["limit"]) if "limit" in args else -1
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_formated_events(
            bucket_id, limit=limit, start=start, end=end
        )
        return events, 200

    # TODO: How to tell expect that it could be a list of events? Until then we can't use validate.
    @api.expect(event)
    @copy_doc(ServerAPI.create_events)
    def post(self, bucket_id):
        """
         Create events in a bucket. This endpoint is used to create one or more events in a bucket.

         @param bucket_id - ID of bucket to create events in

         @return JSON representation of the created event or HTTP status code
        """
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

        # Convert a POST data to a list of events.
        if isinstance(data, dict):
            events = [Event(**data)]
        elif isinstance(data, list):
            events = [Event(**e) for e in data]
        else:
            raise BadRequest("Invalid POST data", "")

        event = current_app.api.create_events(bucket_id, events)
        return event.to_json_dict() if event else None, 200


@api.route("/0/buckets/")
class BucketsResource(Resource):
    # TODO: Add response marshalling/validation
    @copy_doc(ServerAPI.get_buckets)
    def get(self) -> Dict[str, Dict]:
        """
         Get all buckets. This is a shortcut to : meth : ` ~flask. api. Baskets. get_buckets `.


         @return A dictionary of bucket names and their values keyed by bucket
        """
        return current_app.api.get_buckets()


@api.route("/0/buckets/<string:bucket_id>")
class BucketResource(Resource):
    @api.doc(model=bucket)
    @copy_doc(ServerAPI.get_bucket_metadata)
    def get(self, bucket_id):
        """
         Get metadata for a bucket. This is a GET request to the ` ` S3_bucket_metadata ` ` endpoint.

         @param bucket_id - the ID of the bucket to get metadata for

         @return a dict containing bucket metadata or None if not found
        """
        return current_app.api.get_bucket_metadata(bucket_id)

    @api.expect(create_bucket)
    @copy_doc(ServerAPI.create_bucket)
    def post(self, bucket_id):
        """
         Create a bucket. This endpoint requires authentication and will return a 204 if the bucket was created or a 304 if it already exists.

         @param bucket_id - the id of the bucket to create

         @return http code 200 if bucket was created 304 if it
        """
        data = request.get_json()
        bucket_created = current_app.api.create_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
        )
        # Returns a 200 if bucket was created
        if bucket_created:
            return {}, 200
        else:
            return {}, 304

    @api.expect(update_bucket)
    @copy_doc(ServerAPI.update_bucket)
    def put(self, bucket_id):
        """
         Update a bucket. This endpoint is used to update an existing bucket. The request must be made with a JSON object in the body and the data field will be updated to the new data.

         @param bucket_id - the ID of the bucket to update

         @return a 200 response with the updated bucket or an error
        """
        data = request.get_json()
        current_app.api.update_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
            data=data["data"],
        )
        return {}, 200

    @copy_doc(ServerAPI.delete_bucket)
    @api.param("force", "Needs to be =1 to delete a bucket it non-testing mode")
    def delete(self, bucket_id):
        """
         Delete a bucket. Only allowed if aw - server is running in testing mode

         @param bucket_id - ID of bucket to delete

         @return 200 if successful 404 if not ( or on error
        """
        args = request.args
        # DeleteBucketUnauthorized if aw server is running in testing mode or if aw server is running in testing mode or if force 1
        if not current_app.api.testing:
            # DeleteBucketUnauthorized if aw server is running in testing mode or if force 1
            if "force" not in args or args["force"] != "1":
                msg = "Deleting buckets is only permitted if aw-server is running in testing mode or if ?force=1"
                raise Unauthorized("DeleteBucketUnauthorized", msg)

        current_app.api.delete_bucket(bucket_id)
        return {}, 200


# EVENTS


@api.route("/0/buckets/<string:bucket_id>/events")
class EventsResource(Resource):
    # For some reason this doesn't work with the JSONSchema variant
    # Marshalling doesn't work with JSONSchema events
    # @api.marshal_list_with(event)
    @api.doc(model=event)
    @api.param("limit", "the maximum number of requests to get")
    @api.param("start", "Start date of events")
    @api.param("end", "End date of events")
    @copy_doc(ServerAPI.get_events)
    def get(self, bucket_id):
        """
         Get events for a bucket. This endpoint is used to retrieve events that have occurred since the last call to : func : ` ~flask. api. Bucket. create `.

         @param bucket_id - the bucket to get events for.

         @return 200 OK with events in JSON. Example request **. : http Example response **. :
        """
        args = request.args
        limit = int(args["limit"]) if "limit" in args else -1
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_events(
            bucket_id, limit=limit, start=start, end=end
        )
        return events, 200

    # TODO: How to tell expect that it could be a list of events? Until then we can't use validate.
    @api.expect(event)
    @copy_doc(ServerAPI.create_events)
    def post(self, bucket_id):
        """
         Create events in a bucket. This endpoint is used to create one or more events in a bucket.

         @param bucket_id - ID of bucket to create events in

         @return JSON representation of the created event or HTTP status code
        """
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

        # Convert a POST data to a list of events.
        if isinstance(data, dict):
            events = [Event(**data)]
        elif isinstance(data, list):
            events = [Event(**e) for e in data]
        else:
            raise BadRequest("Invalid POST data", "")

        event = current_app.api.create_events(bucket_id, events)
        return event.to_json_dict() if event else None, 200


@api.route("/0/buckets/<string:bucket_id>/events/count")
class EventCountResource(Resource):
    @api.doc(model=fields.Integer)
    @api.param("start", "Start date of eventcount")
    @api.param("end", "End date of eventcount")
    @copy_doc(ServerAPI.get_eventcount)
    def get(self, bucket_id):
        args = request.args
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_eventcount(bucket_id, start=start, end=end)
        return events, 200


@api.route("/0/buckets/<string:bucket_id>/events/<int:event_id>")
class EventResource(Resource):
    @api.doc(model=event)
    @copy_doc(ServerAPI.get_event)
    def get(self, bucket_id: str, event_id: int):
        """
         Get an event by bucket and event id. This is an endpoint for GET requests that need to be handled by the client.

         @param bucket_id - ID of the bucket containing the event
         @param event_id - ID of the event to retrieve

         @return A tuple of HTTP status code and the event if
        """
        logger.debug(
            f"Received get request for event with id '{event_id}' in bucket '{bucket_id}'"
        )
        event = current_app.api.get_event(bucket_id, event_id)
        # Return event and response code
        if event:
            return event, 200
        else:
            return None, 404

    @copy_doc(ServerAPI.delete_event)
    def delete(self, bucket_id: str, event_id: int):
        """
         Delete an event from a bucket. This is a DELETE request to / api / v1 / bucket_ids

         @param bucket_id - ID of bucket to delete event from
         @param event_id - ID of event to delete from bucket

         @return JSON with " success " as a boolean and " message " as
        """
        logger.debug(
            "Received delete request for event with id '{}' in bucket '{}'".format(
                event_id, bucket_id
            )
        )
        success = current_app.api.delete_event(bucket_id, event_id)
        return {"success": success}, 200


@api.route("/0/buckets/<string:bucket_id>/heartbeat")
class HeartbeatResource(Resource):
    def __init__(self, *args, **kwargs):
        """
         Initialize the object. This is the first thing to do before the object is created
        """
        self.lock = Lock()
        super().__init__(*args, **kwargs)

    @api.expect(event, validate=True)
    @api.param(
        "pulsetime", "Largest timewindow allowed between heartbeats for them to merge"
    )
    @copy_doc(ServerAPI.heartbeat)
    def post(self, bucket_id):
        """
        Sends a heartbeat to Sundial. This is an endpoint that can be used to check if an event is active and if it is the case.
        @param bucket_id - The ID of the bucket to send the heartbeat to.
        @return 200 OK if heartbeats were sent 400 Bad Request if there is no credentials in
        """
        heartbeat_data = request.get_json()

        if heartbeat_data['data']['title']=='':
            heartbeat_data['data']['title']=heartbeat_data['data']['app']
        
        # Set default title using the value of 'app' attribute if it's not present in the data dictionary
        heartbeat = Event(**heartbeat_data)

        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # Returns cached credentials if cached credentials are not cached.
        if cached_credentials is None:
            return {"message": "No cached credentials."}, 400

        # The pulsetime parameter is required.
        pulsetime = float(request.args["pulsetime"]) if "pulsetime" in request.args else None
        if pulsetime is None:
            return {"message": "Missing required parameter pulsetime"}, 400

        # This lock is meant to ensure that only one heartbeat is processed at a time,
        # as the heartbeat function is not thread-safe.
        # This should maybe be moved into the api.py file instead (but would be very messy).
        if not self.lock.acquire(timeout=1):
            logger.warning(
                "Heartbeat lock could not be acquired within a reasonable time, this likely indicates a bug."
            )
            return {"message": "Failed to acquire heartbeat lock."}, 500

        try:
            event = current_app.api.heartbeat(bucket_id, heartbeat, pulsetime)
        finally:
            self.lock.release()

        if event:
            return event.to_json_dict(), 200
        else:
            return {"message": "Heartbeat failed."}, 500


# QUERY


@api.route("/0/query/")
class QueryResource(Resource):
    # TODO Docs
    @api.expect(query, validate=True)
    @api.param("name", "Name of the query (required if using cache)")
    def post(self):
        """
         Query an API. This is a POST request to the API endpoint. The query is a JSON object with the following fields : query : the query to be executed timeperiods : the time periods of the query


         @return a JSON object with the results of the query or an error
        """
        name = ""
        # name is the name of the request
        if "name" in request.args:
            name = request.args["name"]
        query = request.get_json()
        try:
            result = current_app.api.query2(
                name, query["query"], query["timeperiods"], False
            )
            return jsonify(result)
        except QueryException as qe:
            traceback.print_exc()
            return {"type": type(qe).__name__, "message": str(qe)}, 400


# EXPORT AND IMPORT


@api.route("/0/export")
class ExportAllResource(Resource):
    @api.doc(model=buckets_export)
    @api.doc(params={"format": "Export format (csv, excel, pdf)",
                     "date": "Date for which to export data (today, yesterday)"})
    def get(self):
        """
        Export events to CSV or CSV format. This endpoint is used to export events from the API and store them in a file for use in other endpoints.
        @return JSON or JSON - encoded data and status of the
        """
        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        export_format = request.args.get("format", "csv")
        _day = request.args.get("date", "today")
        # Invalid date parameter for day is not in today yesterday
        if _day not in ["today", "yesterday"]:
            return {"message": "Invalid date parameter"}, 400

        # Export and process data
        combined_events = []
        if _day == "today":
            day_start = datetime.combine(datetime.now(), time.min)
            day_end = datetime.combine(datetime.now(), time.max)
        else:
            day_start = datetime.combine(datetime.now() - timedelta(days=1), time.min)
            day_end = datetime.combine(datetime.now() - timedelta(days=1), time.max)

        buckets_export = current_app.api.get_dashboard_events(day_start, day_end)
        # Debug: Print buckets_export to ensure it contains data.

        if 'events' in buckets_export:
            combined_events = buckets_export['events']

        df = pd.DataFrame(combined_events)[::-1]
        df["datetime"] = df["timestamp"].apply(lambda x: datetime.strptime(x[:-6], '%Y-%m-%d %H:%M:%S.%f'))
        system_timezone = get_localzone()
        df["datetime"] = df["datetime"].dt.tz_localize(None)
        df["datetime"] = df["datetime"].dt.tz_localize(pytz.utc).dt.tz_convert(system_timezone)
        # df["datetime"] = df["datetime"].dt.tz_convert(system_timezone)
        if _day == "today":
            df = df[df["datetime"].dt.date == datetime.now().date()]
        elif _day == "yesterday":
            df = df[df["datetime"].dt.date == (datetime.now() - timedelta(days=1)).date()]

        # Filter out events with "afk" in application_name and replace it with "Idle Time"
        df.loc[df['application_name'] == 'afk', 'application_name'] = 'Idle Time'

        df["Time Spent"] = df["duration"].apply(lambda x: format_duration(x))
        df['Application Name'] = df['application_name'].str.capitalize()
        df['Event Data'] = df['title'].astype(str)
        df["Event Timestamp"] = df["datetime"].dt.strftime('%H:%M:%S')

        if 'id' in df.columns:
            df.drop('id', axis=1, inplace=True)

        df.insert(0, 'SL NO.', range(1, 1 + len(df)))
        df = df[['SL NO.', 'Application Name', 'Time Spent', 'Event Timestamp', 'Event Data']]

        if export_format == "csv":
            return self.create_csv_response(df, cached_credentials)
        elif export_format == "excel":
            return self.create_excel_response(df, cached_credentials)
        elif export_format == "pdf":
            column_widths = {
                'SL NO.': 50,
                'Application Name': 150,
                'Time Spent': 100,
                'Event Timestamp': 150,
                'Event Data': 300,
            }

            # Apply the formatting to each cell
            for column, width in column_widths.items():
                if column in df.columns:  # Check if the column exists in your DataFrame
                    df[column] = df[column].apply(
                        lambda
                            x: f'<div style="width: {width}px; display: inline-block; word-break: break-word;">{x}</div>')

            # Convert the DataFrame to HTML
            styled_df_html = df.to_html(index=False, escape=False, classes=['table', 'table-bordered'],
                                        justify='center')
            return self.create_pdf_response(styled_df_html, _day, cached_credentials)
        else:
            return {"message": "Invalid export format"}, 400

    def create_csv_response(self, df, user_details):
        """
         Create a response that can be used to export a dataframe as a CSV.

         @param df - The dataframe to export. Must be a : class : ` pandas. DataFrame ` instance.

         @return A : class : ` werkzeug. http. Response ` instance
        """
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        response = make_response(csv_buffer.getvalue())
        response.headers[
            "Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    def create_excel_response(self, df, user_details):
        """
         Create an excel response. This is a wrapper around pandas. to_excel to allow us to write a file to the user's browser

         @param df - The dataframe to be exported

         @return A WSGI response with the data in the excel
        """
        excel_buffer = BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False)
        excel_buffer.seek(0)

        response = make_response(excel_buffer.getvalue())
        response.headers[
            "Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        return response

    def create_pdf_response(self, df, _day, user_details):
        """
         Create a PDF response. It is used to display sundial data in the web browser

         @param df - A dataframe containing the sundial data
         @param _day - The day of the week that the df is in

         @return A string containing the pdf data in the web browser
        """
        """
         Create a PDF response. It is used to display sundial data in the web browser

         @param df - A dataframe containing the sundial data
         @param _day - The day of the week that the df
        """
        css = """
            <style type="text/css">
                body {
                    font-family: Cambria, Georgia, "Times New Roman", Times, serif;
                    font-size: 10px; /* Adjust the font size as needed */
                }
                table {
                    width: 100%; /* Adjust the table width as needed */
                    border: 1px solid #000; /* Black border */
                }
                th, td {
                    text-align: center;
                    padding: 5px; /* Adjust cell padding as needed */
                     /* Allow text to wrap within cells */
                }
                th {
                    background-color: #f2f2f2; /* Gray background for table header */
                }
                td {
                    background-color: #fff; /* White background for table cells */
                    -pdf-word-wrap: CJK;
                }
                .header {
                    width: 100%;
                    text-align: center; /* Center logo */
                }
                .header img {
                    width: 200px; /* Adjust as needed */
                }
                .text-container {
                    text-align: left;
                    margin-top: 10px; /* Spacing after the logo */
                }
            </style>
            """

        header = f"""
            <div class='header'>
                <div class='logo-container'>
                <img src='data:image/png;base64,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' alt='Logo'>
                </div>
                <div class="text-container">
                    <p>Name: {user_details['firstname']}</p>
                    <p>Email: {user_details['email']}</p>
                    <p>Date: {date.today() if _day == "today" else date.today() - timedelta(days=1)}</p>
                </div>
            </div>
            """

        styled_html = f"{css}<body>{header}{df}</body>"
        buffer = BytesIO()
        pdf = pisa.CreatePDF(BytesIO(styled_html.encode("UTF-8")), dest=buffer)
        response = make_response(pdf.dest.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers[
            "Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.pdf"
        return response


# TODO: Perhaps we don't need this, could be done with a query argument to /0/export instead
@api.route("/0/buckets/<string:bucket_id>/export")
class BucketExportResource(Resource):
    @api.doc(model=buckets_export)
    @copy_doc(ServerAPI.export_bucket)
    def get(self, bucket_id):
        bucket_export = current_app.api.export_bucket(bucket_id)
        payload = {"buckets": {bucket_export["id"]: bucket_export}}
        response = make_response(json.dumps(payload))
        filename = "aw-bucket-export_{}.json".format(bucket_export["id"])
        response.headers["Content-Disposition"] = "attachment; filename={}".format(
            filename
        )
        return response


@api.route("/0/user_details")
class UserDetails(Resource):
    @copy_doc(ServerAPI.get_user_details)
    def get(self):
        """
         Get user details. This is a view that can be used to retrieve user details from the API.


         @return A dictionary of user details keyed by user id. Example request **. : http Example response **
        """
        user_details = current_app.api.get_user_details()
        return user_details


@api.route("/0/import")
class ImportAllResource(Resource):
    @api.expect(buckets_export)
    @copy_doc(ServerAPI.import_all)
    def post(self):
        """
         Import buckets from json file or POST request. This is a REST API call


         @return 200 if successful 400 if
        """
        # If import comes from a form in th web-ui
        # Upload multiple files to the server.
        if len(request.files) > 0:
            # web-ui form only allows one file, but technically it's possible to
            # upload multiple files at the same time
            # Import all buckets from the request.
            for filename, f in request.files.items():
                buckets = json.loads(f.stream.read())["buckets"]
                current_app.api.import_all(buckets)
        # Normal import from body
        else:
            buckets = request.get_json()["buckets"]
            current_app.api.import_all(buckets)
        return None, 200


# LOGGING
@api.route("/0/settings")
class SaveSettings(Resource):
    @copy_doc(ServerAPI.save_settings)
    @api.doc(security="Bearer")
    def post(self):
        """
        Save settings to the database. This is a POST request to /api/v1/settings.

        @return: 200 if successful, 400 if there is an error.
        """
        # Parse JSON data sent in the request body
        data = request.get_json()
        if data:
            # Extract 'code' and 'value' from the parsed JSON
            code = data.get('code')
            value = data.get('value')
            print(type(value))
            # Check if both 'code' and 'value' are present
            if code is not None and value is not None:
                # Convert value to JSON string
                value_json = value

                # Save settings to the database
                result = current_app.api.save_settings(code=code, value=value_json)

                # Prepare response dictionary
                result_dict = {
                    "id": result.id,  # Assuming id is the primary key of SettingsModel
                    "code": result.code,
                    "value": value_json  # Use the converted value
                }

                return result_dict, 200  # Return the result dictionary with a 200 status code
            else:
                # Handle the case where 'code' or 'value' is missing in the JSON body
                return {"message": "Both 'code' and 'value' must be provided"}, 400
        else:
            # Handle the case where no JSON is provided
            return {"message": "No settings provided"}, 400


@api.route("/0/getsettings/")
class retrieveSettings(Resource):
    @copy_doc(ServerAPI.get_settings)
    @api.doc(security="Bearer")
    def delete(self):
        """
        Delete settings from the database. This is a DELETE request to /api/v1/settings/{code}.

        @param code: The code associated with the settings to be deleted.
        @return: 200 if successful, 404 if settings not found.
        """
        # Delete settings from the database
        # Assuming current_app.api.delete_settings() is your method to delete settings
        data = request.get_json()
        code = data.get('code')
        result = current_app.api.get_settings(code=code)
        if result:
            return {"message": "Settings deleted successfully", "code": code}, 200
        else:
            return {"message": f"No settings found with code '{code}'"}, 404

@api.route("/0/settings/<string:code>")
class DeleteSettings(Resource):
    @copy_doc(ServerAPI.delete_settings)
    @api.doc(security="Bearer")
    def delete(self, code):
        """
        Delete settings from the database. This is a DELETE request to /api/v1/settings/{code}.

        @param code: The code associated with the settings to be deleted.
        @return: 200 if successful, 404 if settings not found.
        """
        # Delete settings from the database
        # Assuming current_app.api.delete_settings() is your method to delete settings
        result = current_app.api.delete_settings(code=code)
        if result:
            return {"message": "Settings deleted successfully", "code": code}, 200
        else:
            return {"message": f"No settings found with code '{code}'"}, 404



@api.route("/0/getallsettings")
class GetAllSettings(Resource):
    @copy_doc(ServerAPI.retrieve_all_settings)
    @api.doc(security="Bearer")
    def get(self):
        """
        Get settings. This is a GET request to /0/getsettings/{code}.
        """
        settings_dict = db_cache.cache_data("settings_cache")
        if settings_dict is None:
            db_cache.cache_data("settings_cache",current_app.api.retrieve_all_settings())
            settings_dict = db_cache.cache_data("settings_cache")
        print(settings_dict)
        return settings_dict


@api.route("/0/getschedule")
class GetSchedule(Resource):
    @copy_doc(ServerAPI.retrieve_all_settings)
    @api.doc(security="Bearer")
    def get(self):
        """
        Get settings. This is a GET request to /0/getsettings/{code}.
        """
        settings_dict = db_cache.cache_data("settings_cache")
        if settings_dict is None:
            db_cache.cache_data("settings_cache",current_app.api.retrieve_all_settings())
            settings_dict = db_cache.cache_data("settings_cache")
        return json.loads(settings_dict["weekdays_schedule"]),200


@api.route("/0/applicationsdetails")
class SaveApplicationDetails(Resource):
    @api.doc(security="Bearer")
    @copy_doc(ServerAPI.save_application_details)
    def post(self):
        """
        Save application details to the database. This is a POST request to /api/v0/applications.

        @return: 200 if successful, 400 if there is an error.
        """
        # Parse JSON data sent in the request body
        data = request.get_json()
        if data:
            # Extract necessary fields from the parsed JSON
            name = data.get('name')
            url = data.get('url')
            type = data.get('type')
            alias = data.get('alias')
            is_blocked = data.get('is_blocked', False)
            is_ignore_idle_time = data.get('is_ignore_idle_time', False)
            color = data.get('color')

            # Check if the essential field 'name' is present
            # Construct a dictionary with application details
            application_details = {
                "name": name,
                "url": url,
                "type": type,
                "alias": alias,
                "is_blocked": is_blocked,
                "is_ignore_idle_time": is_ignore_idle_time,
                "color": color
            }

            # Remove None values to avoid overwriting with None in the database
            application_details = {k: v for k, v in application_details.items() if v is not None}

            # Save application details to the database
            # Assuming current_app.api.save_application_details() is your method to save application details
            result = current_app.api.save_application_details(application_details)
            if result is not None:
                return {"message": "Application details saved successfully",
                        "result": result.json()}, 200  # Use .json() method to serialize the result
            else:
                return {"message": "Error saving application details"}, 500
        else:
            # Handle the case where no JSON is provided
            return {"message": "No application details provided"}, 400


@api.route("/0/getapplicationdetails")
class getapplicationdetails(Resource):
    @copy_doc(ServerAPI.get_appication_details)
    @api.doc(security="Bearer")
    def get(self):
        """
         Get settings. This is a GET request to / api / v1 /
        """
        return current_app.api.get_appication_details()


@api.route("/0/deleteapplication/<int:application_id>")
class DeleteApplicationDetails(Resource):
    @copy_doc(ServerAPI.delete_application_details)
    @api.doc(security="Bearer")
    def delete(self, application_id):
        """
        Delete application details. This is a DELETE request to /api/v1/deleteapplication/{application_name}
        """
        delete_app = current_app.api.delete_application_details(application_id)
        if delete_app:
            # Convert the ApplicationModel instance to a dictionary
            delete_app_dict = {
                "name": delete_app.name,
                "type": delete_app.type,
                "alias": delete_app.alias,
                "is_blocked": delete_app.is_blocked,
                "is_ignore_idle_time": delete_app.is_ignore_idle_time,
                "color": delete_app.color
            }
            return {"message": "Application details deleted successfully", "result": delete_app_dict}, 200
        else:
            return {"message": "Error deleting application details"}, 500


@api.route("/0/log")
class LogResource(Resource):
    @copy_doc(ServerAPI.get_log)
    def get(self):
        """
         Get logs. This endpoint is used to retrieve log entries. The request must be made by the user to make an HTTP GET request.


         @return 200 OK with log ( dict ) 400 Bad Request if log does not
        """
        return current_app.api.get_log(), 200


@api.route('/0/start/')
class StartModule(Resource):
    @api.doc(security="Bearer")
    @api.doc(params={"module": "Module Name", })
    def get(self):
        """
         Start modules on the server. This will return a message to the client indicating that the module has started.


         @return JSON with the message that was sent to the client
        """
        module_name = request.args.get("module")
        message = manager.start_modules(module_name)
        return jsonify({"message": message})


@api.route('/0/stop/')
class StopModule(Resource):
    @api.doc(security="Bearer")
    @api.doc(params={"module": "Module Name", })
    def get(self):
        """
         Stop a module by name. This is a GET request to / v1 / modules / : id


         @return JSON with message to
        """
        module_name = request.args.get("module")
        message = manager.stop_modules(module_name)
        return jsonify({"message": message})


@api.route('/0/status')
class Status(Resource):
    @api.doc(security="Bearer")
    def get(self):
        """
         Get list of modules. This is a GET request to / modules. The response is a JSON object with a list of modules.


         @return a JSON object with a list of modules in the
        """
        modules = manager.status()
        print(modules)
        return jsonify(modules)


@api.route('/0/idletime')
class idletime(Resource):
    @api.doc(security="Bearer")
    def get(self):
        """
         Get list of modules. This is a GET request to / modules. The response is a JSON object with a list of modules.


         @return a JSON object with a list of modules in the
        """
        module = manager.module_status("aw-watcher-afk")
        if module["is_alive"]:
            manager.stop("aw-watcher-afk")
            message = "idle time has stoppped"
            state = False
        else:
            manager.start("aw-watcher-afk")
            message = "idle time has started"
            state = True
        current_app.api.save_settings("idle_time",state)
        return {"message": message}, 200


@api.route('/0/credentials')
class User(Resource):

    def get(self):
        """
         Get information about the user. This is a GET request to the sundial API.


         @return JSON with firstname lastname and email or False if not
        """
        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        user_key = cached_credentials.get("encrypted_db_key") if cached_credentials else None
        # Returns a JSON response with the user s credentials.
        if user_key is None:
            return False, 404
        else:
            return jsonify(
                {"firstName": cached_credentials.get("firstname"), "lastName": cached_credentials.get("lastname"),
                 "email": cached_credentials.get("email")})


# BUCKETS

@api.route("/0/dashboard/events")
class DashboardResource(Resource):
    def get(self):
        """
         Get dashboard events. GET / api / dashboards / [ id ]?start = YYYYMMDD&end = YYYYMMDD


         @return 200 on success 400 if not found 500 if other
        """
        args = request.args
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_dashboard_events(
            start=start, end=end
        )
        return events, 200


@api.route("/0/dashboard/most_used_apps")
class MostUsedAppsResource(Resource):
    def get(self):
        """
         Get most used apps. This will return a list of apps that have been used in the last 24 hours.


         @return 200 OK if everything worked else 500 Internal Server Error
        """
        args = request.args
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_most_used_apps(
            start=start, end=end
        )
        return events, 200


@api.route("/0/applicationlist")
class ApplicationListResource(Resource):
    @copy_doc(ServerAPI.application_list)
    def get(self):
        applications = current_app.api.application_list()
        return applications, 200

@api.route("/0/idletimesettings")
class IdletimeSettingsResource(Resource):
    def get(self):
        module = manager.module_status("aw-watcher-afk")
        return module["is_alive"], 200

@api.route("/0/launchOnStart")
class LaunchOnStart(Resource):
    def post(self):
        status = request.json.get("status")
        if sys.platform == "darwin":
            
            if status is None:
                return {"error": "Status is required in the request body."}, 400

            if status:
                launch_app()
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start enabled."}, 200
            else:
                delete_launch_app()
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start disabled."}, 200
        elif sys.platform == "win32":
            if status is None:
                return {"error": "Status is required in the request body."}, 400

            if status:
                create_shortcut()
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start enabled."}, 200
            else:
                delete_shortcut()
                current_app.api.save_settings("launch", status)
                return {"message": "Launch on start disabled."}, 200


@api.route("/0/launchOnStartStatus")
class LaunchOnStartStatus(Resource):
    def get(self):
        return check_startup_status()


