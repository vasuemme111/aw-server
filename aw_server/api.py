import functools
from itertools import groupby
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from socket import gethostname

from aw_core.cache import cache_user_credentials
from aw_core.cache import *
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)
from uuid import uuid4
from aw_core.util import decrypt_uuid, encrypt_uuid

import iso8601
from aw_core.dirs import get_data_dir
from aw_core.log import get_log_file_path
from aw_core.models import Event
from aw_query import query2
from aw_transform import heartbeat_merge
import keyring

from .__about__ import __version__
from .exceptions import NotFound
import requests as req
from dateutil import parser

logger = logging.getLogger(__name__)

def get_device_id() -> str:
    path = Path(get_data_dir("aw-server")) / "device_id"
    if path.exists():
        with open(path) as f:
            return f.read()
    else:
        uuid = str(uuid4())
        with open(path, "w") as f:
            f.write(uuid)
        return uuid


def check_bucket_exists(f):
    @functools.wraps(f)
    def g(self, bucket_id, *args, **kwargs):
        if bucket_id not in self.db.buckets():
            raise NotFound("NoSuchBucket", f"There's no bucket named {bucket_id}")
        return f(self, bucket_id, *args, **kwargs)

    return g

def always_raise_for_request_errors(f: Callable[..., req.Response]):
    @functools.wraps(f)
    def g(*args, **kwargs):
        r = f(*args, **kwargs)
        try:
            r.raise_for_status()
        except req.RequestException as e:
            _log_request_exception(e)
            raise e
        return r

    return g

def _log_request_exception(e: req.RequestException):
    r = e.response
    logger.warning(str(e))
    try:
        d = r.json()
        logger.warning(f"Error message received: {d}")
    except json.JSONDecodeError:
        pass

class ServerAPI:
    def __init__(self, db, testing) -> None:
        cache_key = "current_user_credentials"
        cache_user_credentials(cache_key)
        self.db = db
        self.testing = testing
        self.last_event = {}  # type: dict
        self.server_address = "{protocol}://{host}:{port}".format(
            protocol='http', host='14.97.160.178', port='9010'
        )

    def save_settings(self, settings_id, settings_dict) -> None:
        self.db.save_settings(settings_id=settings_id, settings_dict=settings_dict)

    def get_settings(self, settings_id) -> Dict[str, Any]:
        return self.db.retrieve_settings(settings_id)

    def _url(self, endpoint: str):
        return f"{self.server_address}{endpoint}"

    @always_raise_for_request_errors
    def _get(self, endpoint: str, params: Optional[dict] = None) -> req.Response:
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        if params:
            headers.update(params)
        return req.get(self._url(endpoint), headers=headers)

    @always_raise_for_request_errors
    def _post(
        self,
        endpoint: str,
        data: Union[List[Any], Dict[str, Any]],
        params: Optional[dict] = None,
    ) -> req.Response:
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        if params:
            headers.update(params)
        return req.post(
            self._url(endpoint),
            data=bytes(json.dumps(data), "utf8"),
            headers=headers,
            params=params,
        )

    @always_raise_for_request_errors
    def _delete(self, endpoint: str, data: Any = dict()) -> req.Response:
        headers = {"Content-type": "application/json"}
        return req.delete(self._url(endpoint), data=json.dumps(data), headers=headers)


    def init_db(self) -> bool:
        return self.db.init_db()

    def create_user(self, user:Dict[str, Any]):
        endpoint = f"/web/user"
        return self._post(endpoint , user)

    def authorize(self, user:Dict[str, Any]):
        endpoint = f"/web/user/authorize"
        return self._post(endpoint , user)

    def create_company(self, user:Dict[str, Any], token):
        endpoint = f"/web/company"
        return self._post(endpoint , user, {"Authorization" : token})

    def get_user_credentials(self, userId, token):

        cache_key = "current_user_credentials"
        endpoint = f"/web/user/{userId}/credentials"
        user_credentials = self._get(endpoint, {"Authorization": token})

        if user_credentials.status_code == 200 and json.loads(user_credentials.text)["code"] == 'RCI0000':
            credentials_data = json.loads(user_credentials.text)["data"]["credentials"]
            user_data = json.loads(user_credentials.text)["data"]["user"]

            db_key = credentials_data["dbKey"]
            data_encryption_key = credentials_data["dataEncryptionKey"]
            user_key = credentials_data["userKey"]
            email = user_data["email"]
            phone = user_data["phone"]
            firstName = user_data['firstName']
            lastName = user_data['lastName']
            key = user_key
            encrypted_db_key = encrypt_uuid(db_key, key)
            encrypted_data_encryption_key = encrypt_uuid(data_encryption_key, key)
            encrypted_user_key = encrypt_uuid(user_key, key)

            SD_KEYS = {
                "user_key": user_key,
                "encrypted_db_key": encrypted_db_key,
                "encrypted_data_encryption_key": encrypted_data_encryption_key,
                "email": email,
                "phone": phone,
                "firstname": firstName,
                "lastname": lastName,
            }

            store_credentials(cache_key, SD_KEYS)
            serialized_data = json.dumps(SD_KEYS)
            keyring.set_password("SD_KEYS", "SD_KEYS", serialized_data)

            cached_credentials = get_credentials(cache_key)
            key_decoded = cached_credentials.get("user_key")

            decrypted_db_key = decrypt_uuid(encrypted_db_key, key_decoded)
            decrypted_user_key = decrypt_uuid(encrypted_user_key, key_decoded)
            decrypted_data_encryption_key = decrypt_uuid(encrypted_data_encryption_key, key_decoded)
            self.last_event = {}

            print(f"user_key: {decrypted_user_key}")
            print(f"db_key: {decrypted_db_key}")
            print(f"watcher_key: {decrypted_data_encryption_key}")

        return user_credentials

    def get_user_details(self):
        cache_key = "current_user_credentials"
        cached_credentials = get_credentials(cache_key)
        settings_id = 1
        image = self.db.retrieve_settings(settings_id)
        response_data = {"email": cached_credentials.get("email"), "phone": cached_credentials.get("phone"),
                         "firstname": cached_credentials.get("firstname"),
                         "lastname": cached_credentials.get("lastname")}
        if image:
            response_data['ProfileImage'] = image['ProfileImage']
        else:
            response_data['ProfileImage'] = ""
        if not cached_credentials is None:
            return response_data


    def get_info(self) -> Dict[str, Any]:
        """Get server info"""
        payload = {
            "hostname": gethostname(),
            "version": __version__,
            "testing": self.testing,
            "device_id": get_device_id(),
        }
        return payload

    def get_buckets(self) -> Dict[str, Dict]:
        """Get dict {bucket_name: Bucket} of all buckets"""
        logger.debug("Received get request for buckets")
        buckets = self.db.buckets()
        for b in buckets:
            # TODO: Move this code to aw-core?
            last_events = self.db[b].get(limit=1)
            if len(last_events) > 0:
                last_event = last_events[0]
                last_updated = last_event.timestamp + last_event.duration
                buckets[b]["last_updated"] = last_updated.isoformat()
        return buckets

    @check_bucket_exists
    def get_bucket_metadata(self, bucket_id: str) -> Dict[str, Any]:
        """Get metadata about bucket."""
        bucket = self.db[bucket_id]
        return bucket.metadata()

    @check_bucket_exists
    def export_bucket(self, bucket_id: str) -> Dict[str, Any]:
        """Export a bucket to a dataformat consistent across versions, including all events in it."""
        bucket = self.get_bucket_metadata(bucket_id)
        bucket["events"] = self.get_events(bucket_id, limit=-1)
        # Scrub event IDs
        for event in bucket["events"]:
            del event["id"]
        return bucket

    def export_all(self) -> Dict[str, Any]:
        """Exports all buckets and their events to a format consistent across versions"""
        buckets = self.get_buckets()
        exported_buckets = {}
        for bid in buckets.keys():
            exported_buckets[bid] = self.export_bucket(bid)
        return exported_buckets

    def import_bucket(self, bucket_data: Any):
        bucket_id = bucket_data["id"]
        logger.info(f"Importing bucket {bucket_id}")

        # TODO: Check that bucket doesn't already exist
        self.db.create_bucket(
            bucket_id,
            type=bucket_data["type"],
            client=bucket_data["client"],
            hostname=bucket_data["hostname"],
            created=(
                bucket_data["created"]
                if isinstance(bucket_data["created"], datetime)
                else iso8601.parse_date(bucket_data["created"])
            ),
        )

        # scrub IDs from events
        # (otherwise causes weird bugs with no events seemingly imported when importing events exported from aw-server-rust, which contains IDs)
        for event in bucket_data["events"]:
            if "id" in event:
                del event["id"]

        self.create_events(
            bucket_id,
            [Event(**e) if isinstance(e, dict) else e for e in bucket_data["events"]],
        )

    def import_all(self, buckets: Dict[str, Any]):
        for bid, bucket in buckets.items():
            self.import_bucket(bucket)

    def create_bucket(
        self,
        bucket_id: str,
        event_type: str,
        client: str,
        hostname: str,
        created: Optional[datetime] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Create a bucket.

        If hostname is "!local", the hostname and device_id will be set from the server info.
        This is useful for watchers which are known/assumed to run locally but might not know their hostname (like aw-watcher-web).

        Returns True if successful, otherwise false if a bucket with the given ID already existed.
        """
        if created is None:
            created = datetime.now()
        if bucket_id in self.db.buckets():
            return False
        if hostname == "!local":
            info = self.get_info()
            if data is None:
                data = {}
            hostname = info["hostname"]
            data["device_id"] = info["device_id"]
        self.db.create_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            created=created,
            data=data,
        )
        return True

    @check_bucket_exists
    def update_bucket(
        self,
        bucket_id: str,
        event_type: Optional[str] = None,
        client: Optional[str] = None,
        hostname: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update bucket metadata"""
        self.db.update_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            data=data,
        )
        return None

    @check_bucket_exists
    def delete_bucket(self, bucket_id: str) -> None:
        """Delete a bucket"""
        self.db.delete_bucket(bucket_id)
        logger.debug(f"Deleted bucket '{bucket_id}'")
        return None

    @check_bucket_exists
    def get_event(
        self,
        bucket_id: str,
        event_id: int,
    ) -> Optional[Event]:
        """Get a single event from a bucket"""
        logger.debug(
            f"Received get request for event {event_id} in bucket '{bucket_id}'"
        )
        event = self.db[bucket_id].get_by_id(event_id)
        return event.to_json_dict() if event else None

    @check_bucket_exists
    def get_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        """Get events from a bucket"""
        logger.debug(f"Received get request for events in bucket '{bucket_id}'")
        if limit is None:  # Let limit = None also mean "no limit"
            limit = -1
        events = [
            event.to_json_dict() for event in self.db[bucket_id].get(limit, start, end)
        ]
        return event_filter(events)

    @check_bucket_exists
    def create_events(self, bucket_id: str, events: List[Event]) -> Optional[Event]:
        """Create events for a bucket. Can handle both single events and multiple ones.

        Returns the inserted event when a single event was inserted, otherwise None."""
        return self.db[bucket_id].insert(events)

    @check_bucket_exists
    def get_eventcount(
        self,
        bucket_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> int:
        """Get eventcount from a bucket"""
        logger.debug(f"Received get request for eventcount in bucket '{bucket_id}'")
        return self.db[bucket_id].get_eventcount(start, end)

    @check_bucket_exists
    def delete_event(self, bucket_id: str, event_id) -> bool:
        """Delete a single event from a bucket"""
        return self.db[bucket_id].delete(event_id)

    @check_bucket_exists
    def heartbeat(self, bucket_id: str, heartbeat: Event, pulsetime: float) -> Event:
        """
        Heartbeats are useful when implementing watchers that simply keep
        track of a state, how long it's in that state and when it changes.
        A single heartbeat always has a duration of zero.

        If the heartbeat was identical to the last (apart from timestamp), then the last event has its duration updated.
        If the heartbeat differed, then a new event is created.

        Such as:
         - Active application and window title
           - Example: aw-watcher-window
         - Currently open document/browser tab/playing song
           - Example: wakatime
           - Example: aw-watcher-web
           - Example: aw-watcher-spotify
         - Is the user active/inactive?
           Send an event on some interval indicating if the user is active or not.
           - Example: aw-watcher-afk

        Inspired by: https://wakatime.com/developers#heartbeats
        """
        logger.debug(
            "Received heartbeat in bucket '{}'\n\ttimestamp: {}, duration: {}, pulsetime: {}\n\tdata: {}".format(
                bucket_id,
                heartbeat.timestamp,
                heartbeat.duration,
                pulsetime,
                heartbeat.data,
            )
        )

        # The endtime here is set such that in the event that the heartbeat is older than an
        # existing event we should try to merge it with the last event before the heartbeat instead.
        # FIXME: This (the endtime=heartbeat.timestamp) gets rid of the "heartbeat was older than last event"
        #        warning and also causes a already existing "newer" event to be overwritten in the
        #        replace_last call below. This is problematic.
        # Solution: This could be solved if we were able to replace arbitrary events.
        #           That way we could double check that the event has been applied
        #           and if it hasn't we simply replace it with the updated counterpart.

        last_event = None
        if bucket_id not in self.last_event:
            last_events = self.db[bucket_id].get(limit=1)
            if len(last_events) > 0:
                last_event = last_events[0]
        else:
            last_event = self.last_event[bucket_id]

        if last_event:
            if last_event.data == heartbeat.data:
                merged = heartbeat_merge(last_event, heartbeat, pulsetime)
                if merged is not None:
                    # Heartbeat was merged into last_event
                    logger.debug(
                        "Received valid heartbeat, merging. (bucket: {})".format(
                            bucket_id
                        )
                    )
                    self.last_event[bucket_id] = merged
                    self.db[bucket_id].replace_last(merged)
                    return merged
                else:
                    logger.info(
                        "Received heartbeat after pulse window, inserting as new event. (bucket: {})".format(
                            bucket_id
                        )
                    )
            else:
                logger.debug(
                    "Received heartbeat with differing data, inserting as new event. (bucket: {})".format(
                        bucket_id
                    )
                )
        else:
            logger.info(
                "Received heartbeat, but bucket was previously empty, inserting as new event. (bucket: {})".format(
                    bucket_id
                )
            )

        self.db[bucket_id].insert(heartbeat)
        self.last_event[bucket_id] = heartbeat
        return heartbeat

    def query2(self, name, query, timeperiods, cache):
        result = []
        for timeperiod in timeperiods:
            period = timeperiod.split("/")[
                :2
            ]  # iso8601 timeperiods are separated by a slash
            starttime = iso8601.parse_date(period[0])
            endtime = iso8601.parse_date(period[1])
            query = "".join(query)
            result.append(query2.query(name, query, starttime, endtime, self.db))
        return result

    # TODO: Right now the log format on disk has to be JSON, this is hard to read by humans...
    def get_log(self):
        """Get the server log in json format"""
        payload = []
        with open(get_log_file_path()) as log_file:
            for line in log_file.readlines()[::-1]:
                payload.append(json.loads(line))
        return payload, 200

    @check_bucket_exists
    def get_formated_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        """Get events from a bucket"""
        logger.debug(f"Received get request for events in bucket '{bucket_id}'")
        if limit is None:  # Let limit = None also mean "no limit"
            limit = -1
        events = [
            event.to_json_dict() for event in self.db[bucket_id].get(limit, start, end)
        ]

        data = events
        # Sort the data by the "app" key and timestamp
        data.sort(key=lambda x: (x['data']['app'], x['timestamp']))

        # Group the data by the "app" key
        grouped_data = {key: list(group) for key, group in groupby(data, key=lambda x: x['data']['app'])}

        # Convert duration to timedelta for easier manipulation
        for app, entries in grouped_data.items():
            for entry in entries:
                entry['duration'] = timedelta(seconds=entry['duration'])

        # Custom JSON encoder for timedelta
        class TimedeltaEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, timedelta):
                    return str(obj)
                return super().default(obj)

        # Prepare the final result in the desired format
        result = []
        for app, entries in grouped_data.items():
            total_duration = sum((entry['duration'] for entry in entries), timedelta())

            formatted_entry = {
                "app": app,
                "startTime": entries[0]['timestamp'],
                "endTime": entries[-1]['timestamp'],
                "events": [{
                    "id": str(entry['id']),
                    "app": entry['data']['app'],
                    "title": entry['data']['title'],
                    "startTime": entry['timestamp'],
                    "endTime": (datetime.fromisoformat(entry['timestamp']) + entry['duration']).isoformat(),
                } for entry in entries],
                "totalHours": f"{int(total_duration.total_seconds() // 3600):02}",
                "totalMinutes": f"{int((total_duration.total_seconds() % 3600) // 60):02}",
                "totalSeconds": f"{int(total_duration.total_seconds()):02}"
            }

            result.append(formatted_entry)

        # Convert the result to JSON using the custom encoder
        json_result = json.dumps(result, cls=TimedeltaEncoder)

        # Print the JSON result
        # print(json_result)
        return json_result

def datetime_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()

def event_filter(data):

    if (
        isinstance(data, list)
        and len(data) > 0
    ):
        events = sorted(data, key=lambda x: parser.isoparse(x["timestamp"]).timestamp())
        formated_events = []
        start_date_time = None
        start_hour = 24
        start_min = 59

        for e in events:
            event_start = parser.isoparse(e["timestamp"])
            event_end = event_start + timedelta(seconds=e["duration"])
            # color = getRandomColorVariants()  # Assuming you have this function implemented

            new_event = {
                **e,
                "start": event_start.isoformat(),
                "end": event_end.isoformat(),
                "event_id": e["id"],
                "title": e["data"]["title"],
                # "light": color["light"],
                # "dark": color["dark"],
            }
            formated_events.append(new_event)

            if start_hour > event_start.hour or (start_hour == event_start.hour and start_min > event_start.minute):
                start_hour = event_start.hour
                start_min = event_start.minute
                start_date_time = event_start


        # Sort the data by the "app" key and timestamp
        events.sort(key=lambda x: (x['data']['app'], x['timestamp']))

        # Group the data by the "app" key
        grouped_data = {key: list(group) for key, group in groupby(events, key=lambda x: x['data']['app'])}

        # Convert duration to timedelta for easier manipulation
        for app, entries in grouped_data.items():
            for entry in entries:
                entry['duration'] = timedelta(seconds=entry['duration'])

        # Prepare the final result in the desired format
        result = []
        for app, entries in grouped_data.items():
            total_duration = sum((entry['duration'] for entry in entries), timedelta())

            formatted_entry = {
                "app": app,
                "startTime": entries[0]['timestamp'],
                "endTime": entries[-1]['timestamp'],
                "events": [{
                    "id": str(entry['id']),
                    "app": entry['data']['app'],
                    "title": entry['data']['title'],
                    "startTime": entry['timestamp'],
                    "endTime": (datetime.fromisoformat(entry['timestamp']) + entry['duration']).isoformat(),
                } for entry in entries],
                "totalHours": f"{int(total_duration.total_seconds() // 3600):02}",
                "totalMinutes": f"{int((total_duration.total_seconds() % 3600) // 60):02}",
                "totalSeconds": f"{int(total_duration.total_seconds()):02}"
            }

            result.append(formatted_entry)

        # Convert events list to JSON object using custom serializer
        events_json = json.dumps({
            "events": formated_events,
            "start_hour": start_hour,
            "start_min": start_min,
            "start_date_time": start_date_time,
            "most_used_apps" : result
        }, default=datetime_serializer)

        return json.loads(events_json)  # Parse the JSON string to a Python object