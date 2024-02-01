import getpass
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
        print(buckets_export)  # Debug: Print buckets_export to ensure it contains data.

        if 'events' in buckets_export:
            combined_events = buckets_export['events']

        df = pd.DataFrame(combined_events)[::-1]
        print("------>",df)
        df["datetime"] = pd.to_datetime(df["timestamp"], format='%Y-%m-%d %H:%M:%S.%f%z')
        system_timezone = get_localzone()
        df["datetime"] = df["datetime"].dt.tz_convert(system_timezone)
        if _day == "today":
            df = df[df["datetime"].dt.date == datetime.now().date()]
        elif _day == "yesterday":
            df = df[df["datetime"].dt.date == (datetime.now() - timedelta(days=1)).date()]

        df["Time Spent"] = df["duration"].apply(lambda x: format_duration(x))
        df['Application Name'] = df['data'].apply(lambda x: x.get('app', 'Unknown'))
        df['Event Data'] = df['data'].apply(lambda x: x.get('title') if 'title' in x else x.get('status', ''))
        df["Event Timestamp"] = df["datetime"].dt.strftime('%H:%M:%S')

        if 'id' in df.columns:
            df.drop('id', axis=1, inplace=True)

        df.insert(0, 'SL NO.', range(1, 1 + len(df)))
        df = df[['SL NO.', 'Application Name', 'Time Spent', 'Event Timestamp', 'Event Data']]

        if export_format == "csv":
            return self.create_csv_response(df)
        elif export_format == "excel":
            return self.create_excel_response(df)
        elif export_format == "pdf":
            column_widths = {
                'SL NO.': 50,
                'Application Name': 150,
                'Time Spent': 100,
                'Event Timestamp': 150,
                'Event Data': 300,
            }
            for column, width in column_widths.items():
                df[column] = df[column].apply(
                    lambda x: f'<div style="width: {width}px; word-wrap: break-word;">{x}</div>')
            styled_df_html = df.to_html(index=False, escape=False, classes=['table', 'table-bordered'],
                                        justify='center')
            return self.create_pdf_response(styled_df_html, _day)
        else:
            return {"message": "Invalid export format"}, 400

    def create_csv_response(self, df):
        """
         Create a response that can be used to export a dataframe as a CSV.

         @param df - The dataframe to export. Must be a : class : ` pandas. DataFrame ` instance.

         @return A : class : ` werkzeug. http. Response ` instance
        """
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        response = make_response(csv_buffer.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=aw-export.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    def create_excel_response(self, df):
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
        response.headers["Content-Disposition"] = "attachment; filename=aw-export.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        return response

    def create_pdf_response(self, df, _day):
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
        pdf_data = "s"
        cache_key = "sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        css = """
            <style type="text/css">
                body {
                    font-family: Cambria, Georgia, "Times New Roman", Times, serif;
                    font-size: 10px; /* Adjust the font size as needed */
                }
                table {
                    width: 100%; /* Adjust the table width as needed */
                    border: 1px solid #ddd;
                }
                th, td {
                    text-align: center;
                    padding: 5px; /* Adjust cell padding as needed */
                }
                th {
                    background-color: #f2f2f2; /* Gray background for table header */
                }
                td {
                    background-color: #fff; /* White background for table cells */
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
                    <p>Name: {cached_credentials['firstname']}</p>
                    <p>Email: {cached_credentials['email']}</p>
                    <p>Date: {date.today() if _day == "today" else date.today() - timedelta(days=1)}</p>
                </div>
            </div>
            """

        styled_html = f"{css}<body>{header}{df}</body>"
        buffer = BytesIO()
        pdf = pisa.CreatePDF(BytesIO(styled_html.encode("UTF-8")), dest=buffer)
        response = make_response(pdf.dest.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "attachment; filename=aw_export.pdf"
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
