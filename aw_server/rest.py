import getpass
import os
import traceback
from functools import wraps
from threading import Lock
from typing import Dict
from tzlocal import get_localzone
from xhtml2pdf import pisa
from aw_core.util import authenticate, is_internet_connected, reset_user
import pandas as pd
from datetime import datetime, timedelta, date, time
import iso8601
from aw_core import schema
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
        heartbeat = Event(**request.get_json())

        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # Returns cached credentials if cached credentials are not cached.
        if cached_credentials == None:
            return None
        # The pulsetime parameter is required.
        if "pulsetime" in request.args:
            pulsetime = float(request.args["pulsetime"])
        else:
            raise BadRequest("MissingParameter", "Missing required parameter pulsetime")

        # This lock is meant to ensure that only one heartbeat is processed at a time,
        # as the heartbeat function is not thread-safe.
        # This should maybe be moved into the api.py file instead (but would be very messy).
        aquired = self.lock.acquire(timeout=1)
        # Heartbeat lock is not aquired within a reasonable time
        if not aquired:
            logger.warning(
                "Heartbeat lock could not be aquired within a reasonable time, this likely indicates a bug."
            )
        try:
            event = current_app.api.heartbeat(bucket_id, heartbeat, pulsetime)
        finally:
            self.lock.release()
        return event.to_json_dict(), 200


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
        df["datetime"] = pd.to_datetime(df["timestamp"], format='%Y-%m-%d %H:%M:%S.%f%z')
        system_timezone = get_localzone()
        df["datetime"] = df["datetime"].dt.tz_convert(system_timezone)
        if _day == "today":
            df = df[df["datetime"].dt.date == datetime.now().date()]
        elif _day == "yesterday":
            df = df[df["datetime"].dt.date == (datetime.now() - timedelta(days=1)).date()]

        df["Time Spent"] = df["duration"].apply(lambda x: format_duration(x))
        df['Application Name'] = df['application_name']
        df['Event Data'] = df['title'].astype(str)
        df["Event Timestamp"] = df["datetime"].dt.strftime('%H:%M:%S')

        if 'id' in df.columns:
            df.drop('id', axis=1, inplace=True)

        df.insert(0, 'SL NO.', range(1, 1 + len(df)))
        df = df[['SL NO.', 'Application Name', 'Time Spent', 'Event Timestamp', 'Event Data']]

        if export_format == "csv":
            return self.create_csv_response(df,cached_credentials)
        elif export_format == "excel":
            return self.create_excel_response(df,cached_credentials)
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
                        lambda x: f'<div style="width: {width}px; display: inline-block; word-break: break-word;">{x}</div>')

            # Convert the DataFrame to HTML
            styled_df_html = df.to_html(index=False, escape=False, classes=['table', 'table-bordered'],
                                        justify='center')
            return self.create_pdf_response(styled_df_html, _day,cached_credentials)
        else:
            return {"message": "Invalid export format"}, 400

    def create_csv_response(self, df,user_details):
        """
         Create a response that can be used to export a dataframe as a CSV.

         @param df - The dataframe to export. Must be a : class : ` pandas. DataFrame ` instance.

         @return A : class : ` werkzeug. http. Response ` instance
        """
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        response = make_response(csv_buffer.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    def create_excel_response(self, df,user_details):
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
        response.headers["Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        return response

    def create_pdf_response(self, df, _day,user_details):
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

        current_file_directory = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(current_file_directory, "logo/Sundial.png")
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
                <img src='{logo_path}' alt='Logo'>
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
        response.headers["Content-Disposition"] = f"attachment; filename={user_details['firstname']}_{datetime.now()}.pdf"
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
    def post(self):
        """
        Save settings to the database. This is a POST request to /api/v1/settings.

        @return: 200 if successful, 400 if there is an error.
        """
        # Parse JSON data sent in the request body
        data = request.get_json()
        if data:
            # Extract 'code' and 'value' from the parsed JSON
            code = data['code']
            value = data['value']

            # Check if both 'code' and 'value' are present
            if code is not None and value is not None:
                # Save settings to the database
                # Assuming current_app.api.save_settings() is your method to save settings
                result = current_app.api.save_settings(code=code, value=json.dumps(value))
                return result, 200  # Return the result with a 200 status code
            else:
                # Handle the case where 'code' or 'value' is missing in the JSON body
                return {"message": "Both 'code' and 'value' must be provided"}, 400
        else:
            # Handle the case where no JSON is provided
            return {"message": "No settings provided"}, 400


@api.route("/0/getsettings")
class getSettings(Resource):
    @copy_doc(ServerAPI.get_settings)
    def get(self):
        """
         Get settings. This is a GET request to / api / v1 /
        """
        settings_id = 1
        current_app.api.get_settings(settings_id)

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
            type = data.get('type')
            alias = data.get('alias')
            is_blocked = data.get('is_blocked', False)
            is_ignore_idle_time = data.get('is_ignore_idle_time', False)
            color = data.get('color')

            # Check if the essential field 'name' is present
            if name:
                # Construct a dictionary with application details
                application_details = {
                    "name": name,
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
                return {"message": "Application details saved successfully", "result": result.json()}, 200  # Use .json() method to serialize the result
            else:
                # Handle the case where 'name' is missing in the JSON body
                return {"message": "The 'name' field is required"}, 400
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
