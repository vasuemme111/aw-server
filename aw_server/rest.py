import getpass
import json
import traceback
from functools import wraps
from threading import Lock
from typing import Dict
from aw_core.util import authenticate, is_internet_connected, reset_user
import pandas as pd
from datetime import datetime, timedelta
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
import os
from flask_restx import Api, Resource, fields
import jwt
import keyring
import sys
from io import BytesIO
from . import logger
from .api import ServerAPI
from .exceptions import BadRequest, Unauthorized
from aw_qt.manager import Manager

manager = Manager()


def host_header_check(f):
    """
    Protects against DNS rebinding attacks (see https://github.com/ActivityWatch/activitywatch/security/advisories/GHSA-v9fg-6g9j-h4x4)

    Some discussion in Syncthing how they do it: https://github.com/syncthing/syncthing/issues/4819
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        if("/heartbeat" not in request.path and request.path != '/api/0/buckets/'and request.path != '/api/swagger.json'and request.path != '/api/0/ralvie/login' and request.path != '/api/0/login'  and request.path != '/api/0/user' and request.method != 'OPTIONS'):
            token = request.headers.get("Authorization")
            if not token:
                print("Token is missing")
                return {"message": "Token is missing"}, 401  # Return 401 Unauthorized if token is not present
            else:
                if("/company" not in request.path):
                    cache_key = "current_user_credentials"
                    cached_credentials = cache_user_credentials(cache_key)
                    user_key = cached_credentials.get("user_key")

                    try:
                        jwt.decode(token.replace("Bearer ",""),key=user_key, algorithms=["HS256"])
                    except Exception as e:
                        print("Invalid token")
                        return {"message": "Invalid token"}, 401
        server_host = current_app.config["HOST"]
        req_host = request.headers.get("host", None)
        if server_host == "0.0.0.0":
            logger.warning(
                "Server is listening on 0.0.0.0, host header check is disabled (potential security issue)."
            )
        elif req_host is None:
            return {"message": "host header is missing"}, 400
        else:
            if req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
                return {"message": f"host header is invalid (was {req_host})"}, 400
        return f(*args, **kwargs)

    return decorator


blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/", decorators=[host_header_check])

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
    """Decorator that copies another functions docstring to the decorated function.
    Used to copy the docstrings in ServerAPI over to the flask-restplus Resources.
    (The copied docstrings are then used by flask-restplus/swagger)"""

    def decorator(f):
        f.__doc__ = api_method.__doc__
        return f

    return decorator


# SERVER INFO


@api.route("/0/info")
class InfoResource(Resource):
    @api.marshal_with(info)
    @copy_doc(ServerAPI.get_info)
    def get(self) -> Dict[str, Dict]:
        return current_app.api.get_info()


# Users


@api.route("/0/user")
class UserResource(Resource):
    def post(self):
        cache_key = "current_user_credentials"
        cached_credentials = cache_user_credentials(cache_key)
        if not is_internet_connected():
            print("Please connect to internet and try again.")
        data = request.get_json()
        if not data['email']:
            return {"message": "User name is mandatory"}, 400
        elif not data['password']:
            return {"message": "Password is mandatory"}, 400
        if cached_credentials is not None:
            user = cached_credentials.get("encrypted_db_key")
        else:
            user = None
        if True:
            result = current_app.api.create_user(data)
            if result.status_code == 200 and json.loads(result.text)["code"] == 'UASI0001':
                userPayload = {
                    "userName": data['email'],
                    "password": data['password']
                }
                authResult = current_app.api.authorize(userPayload)

                if 'company' not in data:
                    return json.loads(authResult.text), 200

                if authResult.status_code == 200 and json.loads(authResult.text)["code"] == 'RCI0000':
                    token = json.loads(authResult.text)["data"]["access_token"]
                    id = json.loads(authResult.text)["data"]["id"]
                    companyPayload = {
                        "name": data['company'],
                        "code": data['company'],
                        "status": "ACTIVE"
                    }

                    companyResult = current_app.api.create_company(companyPayload, 'Bearer ' + token)

                    if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
                        current_app.api.get_user_credentials(id, 'Bearer ' + token)
                        init_db = current_app.api.init_db()
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
        data = request.get_json()
        token = request.headers.get("Authorization")
        if not token:
            return {"message": "Token is required"}, 401
        if not data['name']:
            return {"message": "Company name is mandatory"}, 400
        companyPayload = {
            "name": data['name'],
            "code": data['code'],
            "status": "ACTIVE"
        }

        companyResult = current_app.api.create_company(companyPayload, token)

        if companyResult.status_code == 200 and json.loads(companyResult.text)["code"] == 'UASI0006':
            return json.loads(companyResult.text), 200
        else:
            return json.loads(companyResult.text), companyResult.status_code


# Login by system credentials
@api.route("/0/login")
class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        cache_key = "current_user_credentials"
        cached_credentials = cache_user_credentials(cache_key)
        user_key = cached_credentials.get("user_key")
        print(user_key)
        if user_key:
            if authenticate(data['userName'], data['password']):
                encoded_jwt = jwt.encode({"user": data['userName'], "email": cached_credentials.get("email"),
                                          "phone": cached_credentials.get("phone")}, user_key, algorithm="HS256")
                return {"code": "SDI0000", "message": "Success", "data": {"token": encoded_jwt}}, 200
            else:
                return {"code": "SDE0000", "message": "Username or password is wrong"}, 200
        else:
            return {"message": "User does not exist"}, 200

    def get(self):
        data = request.get_json()
        cache_key = "current_user_credentials"
        cached_credentials = cache_user_credentials(cache_key)
        if cached_credentials is not None:
            user_key = cached_credentials.get("encrypted_db_key")
        else:
            user_key = None
        if user_key:
            return {"message": "User exist"}, 200
        else:
            return {"message": "User does not exist"}, 401


# Login by ralvie cloud
@api.route("/0/ralvie/login")
class RalvieLoginResource(Resource):
    def post(self):
        cache_key = "current_user_credentials"
        # Check Internet Connectivity
        response_data = {}
        if not is_internet_connected():
            return jsonify({"message": "Please connect to the internet and try again."}), 200

        # Parse Request Data
        data = request.get_json()
        user_name = data.get('userName')
        password = data.get('password')

        if not user_name:
            return jsonify({"message": "User name is mandatory"}), 400
        elif not password:
            return jsonify({"message": "Password is mandatory"}), 400

        # Reset User Data
        reset_user()

        # Authenticate User
        auth_result = current_app.api.authorize(data)

        if auth_result.status_code == 200 and json.loads(auth_result.text)["code"] == 'UASI0011':
            # Retrieve Cached User Credentials
            cached_credentials = cache_user_credentials(cache_key)

            # Get the User Key
            user_key = cached_credentials.get("encrypted_db_key") if cached_credentials else None

            if user_key is None:
                token = json.loads(auth_result.text)["data"]["access_token"]
                user_id = json.loads(auth_result.text)["data"]["id"]
                current_app.api.get_user_credentials(user_id, 'Bearer ' + token)
                init_db = current_app.api.init_db()

                if not init_db:
                    reset_user()
                    return {"message": "Something went wrong"}, 500

            # Generate JWT
            payload = {
                "user": getpass.getuser(),
                "email": cache_user_credentials(cache_key).get("email"),
                "phone": cache_user_credentials(cache_key).get("phone")
            }
            encoded_jwt = jwt.encode(payload, cache_user_credentials(cache_key).get("user_key"), algorithm="HS256")

            # Response
            response_data['code'] = "UASI0011",
            response_data["message"] = json.loads(auth_result.text)["message"],
            response_data["data"]: {"token": "Bearer " + encoded_jwt}
            return {"code": "UASI0011", "message": json.loads(auth_result.text)["message"],
                    "data": {"token": "Bearer " + encoded_jwt}}, 200
        else:
            return {"code": json.loads(auth_result.text)["code"], "message": json.loads(auth_result.text)["message"], "data" : json.loads(auth_result.text)["data"]}, 200


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
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

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
        return current_app.api.get_buckets()


@api.route("/0/buckets/<string:bucket_id>")
class BucketResource(Resource):
    @api.doc(model=bucket)
    @copy_doc(ServerAPI.get_bucket_metadata)
    def get(self, bucket_id):
        return current_app.api.get_bucket_metadata(bucket_id)

    @api.expect(create_bucket)
    @copy_doc(ServerAPI.create_bucket)
    def post(self, bucket_id):
        data = request.get_json()
        bucket_created = current_app.api.create_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
        )
        if bucket_created:
            return {}, 200
        else:
            return {}, 304

    @api.expect(update_bucket)
    @copy_doc(ServerAPI.update_bucket)
    def put(self, bucket_id):
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
        args = request.args
        if not current_app.api.testing:
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
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

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
        logger.debug(
            f"Received get request for event with id '{event_id}' in bucket '{bucket_id}'"
        )
        event = current_app.api.get_event(bucket_id, event_id)
        if event:
            return event, 200
        else:
            return None, 404

    @copy_doc(ServerAPI.delete_event)
    def delete(self, bucket_id: str, event_id: int):
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
        self.lock = Lock()
        super().__init__(*args, **kwargs)

    @api.expect(event, validate=True)
    @api.param(
        "pulsetime", "Largest timewindow allowed between heartbeats for them to merge"
    )
    @copy_doc(ServerAPI.heartbeat)
    def post(self, bucket_id):
        heartbeat = Event(**request.get_json())

        cache_key = "current_user_credentials"
        cached_credentials = cache_user_credentials(cache_key)
        if cached_credentials == None:
            return None
        if "pulsetime" in request.args:
            pulsetime = float(request.args["pulsetime"])
        else:
            raise BadRequest("MissingParameter", "Missing required parameter pulsetime")

        # This lock is meant to ensure that only one heartbeat is processed at a time,
        # as the heartbeat function is not thread-safe.
        # This should maybe be moved into the api.py file instead (but would be very messy).
        aquired = self.lock.acquire(timeout=1)
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
        name = ""
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
        export_format = request.args.get("format", "csv", )
        date = request.args.get("date", "today")
        if date not in ["today", "yesterday"]:
            return {"message": "Invalid date parameter"}, 400
        combined_events = []
        buckets_export = current_app.api.export_all()
        for key, value in buckets_export.items():
            combined_events.extend(value['events'])
        df = pd.DataFrame(combined_events)
        df["timestamp"] = pd.to_datetime(df["timestamp"], format='ISO8601')
        if date == "today":
            df = df[df["timestamp"].dt.date == datetime.now().date()]
        elif date == "yesterday":
            df = df[df["timestamp"].dt.date == (datetime.now() - timedelta(days=1)).date()]
        df["duration"] = df["duration"].apply(lambda x: f"{x:.3f}")
        df['data'] = df['data']

        if export_format == "csv":
            return self.create_csv_response(df)
        elif export_format == "excel":
            return self.create_excel_response(df)
        elif export_format == "pdf":
            return self.create_pdf_response(df)
        else:
            return {"message": "Invalid export format"}, 400

    def create_csv_response(self, df):
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)

        response = make_response(csv_buffer.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=aw-export.csv"
        response.headers["Content-Type"] = "text/csv"

        return response

    def create_excel_response(self, df):
        excel_buffer = BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.tz_localize(None)
            df.to_excel(writer, index=False)
        excel_buffer.seek(0)

        response = make_response(excel_buffer.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=aw-export.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        return response

    def create_pdf_response(self, df):
        css = """
        <style type="text/css">
        table {
            border-collapse: collapse;
            width: 100%;
            border: 1px solid #ddd;
        }
        th, td {
            text-align: left;
            padding: 8px;
        }
        tr:nth-child(even){background-color: #f2f2f2}
        th {
            background-color: #4CAF50;
            color: white;
        }
        </style>
        """

        html_data = df.to_html(index=False)
        styled_html = f"{css}<body>{html_data}</body>"

        options = {
            'page-size': 'Letter',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ],
            'no-outline': None
        }

        if sys.platform == "win32":
            import pdfkit
            current_dir = os.path.dirname(os.path.abspath(__file__))
            activitywatch_dir = os.path.dirname(os.path.dirname(current_dir))
            pdfkit_config = pdfkit.configuration(wkhtmltopdf=activitywatch_dir + "/wkhtmltopdf.exe")
            pdf_data = pdfkit.from_string(styled_html, False, options=options, configuration=pdfkit_config)
            response = make_response(pdf_data)
            response.headers["Content-Type"] = "application/pdf"
            response.headers["Content-Disposition"] = "attachment; filename=aw_export.pdf"
            print(type(response))
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
        user_details = current_app.api.get_user_details()
        return user_details


@api.route("/0/import")
class ImportAllResource(Resource):
    @api.expect(buckets_export)
    @copy_doc(ServerAPI.import_all)
    def post(self):
        # If import comes from a form in th web-ui
        if len(request.files) > 0:
            # web-ui form only allows one file, but technically it's possible to
            # upload multiple files at the same time
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
    def post(self):
        settings_id = 1
        settings = request.get_json()  # This will parse JSON data sent in the request body
        if settings:
            # Assuming current_app.api.save_settings() is your method to save settings
            return current_app.api.save_settings(settings_id, settings_dict=settings), 200
        else:
            # Handle the case where no JSON is provided
            return {"message": "No settings provided"}, 400


@api.route("/0/getsettings")
class getSettings(Resource):
    @copy_doc(ServerAPI.get_settings)
    def get(self):
        settings_id = 1
        current_app.api.get_settings(settings_id)


@api.route("/0/log")
class LogResource(Resource):
    @copy_doc(ServerAPI.get_log)
    def get(self):
        return current_app.api.get_log(), 200


@api.route('/0/start/')
class StartModule(Resource):
    @api.doc(params={"module": "Module Name", })
    def get(self):
        module_name = request.args.get("module")
        message = manager.start_modules(module_name)
        return jsonify({"message": message})


@api.route('/0/stop/')
class StopModule(Resource):
    @api.doc(params={"module": "Module Name", })
    def get(self):
        module_name = request.args.get("module")
        message = manager.stop_modules(module_name)
        return jsonify({"message": message})


@api.route('/0/status')
class Status(Resource):
    def get(self):
        modules = manager.status()
        return jsonify(modules)
