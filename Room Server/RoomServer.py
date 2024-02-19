#!/usr/bin/env python3

import argparse
import asyncio
import collections
import json
import pprint
import sys
import socket
import selectors
import time
import types
import urllib

# Insight Webserver
from flask import Flask, Blueprint, render_template, render_template_string, send_from_directory, request, redirect
#from flask_sock import Sock
import simple_websocket
from markupsafe import escape
import threading
from werkzeug.serving import make_server
import os


parser = argparse.ArgumentParser(description="Route and Inspect Messages for Cryptographic Protocols")
parser.add_argument("-r", "--bind-router", nargs=2, metavar=("router_host", "router_port"), default=["localhost", "25080"], help="Bind router to <router_host> <router_port>")
parser.add_argument("-i", "--bind-inspector", nargs=2, metavar=("inspector_host", "inspector_port"), default=["localhost", "11080"], help="Bind inspector to <inspector_host> <inspector_port>")
parser.add_argument("-p", "--router-connection-password", default="")
parser.add_argument("-u", "--inspector-url", default="http://localhost:11080", help="External URL for inspector with protocol part, e.g. 'http://localhost:11080' or 'https://dom.tld/path'")

# EXAMPLE COMMAND LINE
# -r '' 25080 -i '' 11080 -p 'Drehkreuz64' -u https://itvia.co

args = parser.parse_args()

# args.{router_host,router_port}
# router_host
# router_port
router_host = args.bind_router[0]
try:
    router_port = int(args.bind_router[1])
except ValueError as e:
    raise argparse.ArgumentTypeError(f"-r, --bind-router <host> <port>: port {args.bind_router[1]} is not an integer")

# args.{inspector_host,inspector_port}
# inspector_host
# inspector_port
inspector_host = args.bind_inspector[0]
try:
    inspector_port = int(args.bind_inspector[1])
except ValueError as e:
    raise argparse.ArgumentTypeError(f"-i, --bind-inspector <host> <port>: port {args.bind_inspector[1]} is not an integer")

# args.router_connection_password
# router_connection_password
router_connection_password = args.router_connection_password

# args.inspector_url
# inspector_url_http
# inspector_url_ws
# inspector_application_root
inspector_url_parsed = urllib.parse.urlparse(args.inspector_url)
if inspector_url_parsed.scheme == "":
    inspector_url_parsed = inspector_url_parsed._replace(scheme="http")
# fix bug in urllib.parse.urlparse:
#if inspector_url_parsed.netloc == "":
#    raise argparse.ArgumentTypeError(f"-u --inspector-url <url>: {args.inspector_url} is not a valid URL")
if inspector_url_parsed.netloc == "" and inspector_url_parsed.path == "":
    raise argparse.ArgumentTypeError(f"-u --inspector-url <url>: {args.inspector_url} is not a valid URL")
if inspector_url_parsed.netloc == "":
    s = inspector_url_parsed.path.split("/", 1)
    inspector_url_parsed = inspector_url_parsed._replace(netloc=s[0])
    if len(s) == 1:
        inspector_url_parsed = inspector_url_parsed._replace(path="")
    else:
        inspector_url_parsed = inspector_url_parsed._replace(path="/" + s[1])
# supported schemes: http and https
if inspector_url_parsed.scheme != "http" and inspector_url_parsed.scheme != "https":
    raise argparse.ArgumentTypeError(f"-u --inspector-url <url>: scheme of {args.inspector_url} is not http(s)")
inspector_url_http = urllib.parse.urlunparse(inspector_url_parsed)
inspector_url_ws = "ws" + inspector_url_http[4:]
inspector_application_root = inspector_url_parsed.path + inspector_url_parsed.query + inspector_url_parsed.fragment


sel = selectors.DefaultSelector()
pp = pprint.PrettyPrinter(indent=4)

class ECPoint:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def __str__(self):
        return f"ECPoint[{self.x},{self.y}]"
    def __repr__(self):
        return str(self)


class MessageDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)
    def object_hook(self, dct):
        if "__type" in dct:
            if dct["__type"] == "ECPoint":
                if not "x" in dct or not "y" in dct:
                    raise json.decoder.JSONDecodeError(f"Type ECPoint: Expected integer coordinates x and y in {dct}")
                if not isinstance(dct["x"], int) or not isinstance(dct["y"], int):
                    raise json.decoder.JSONDecodeError(f"Type ECPoint: Expected integer coordinates x and y in {dct}")
                return ECPoint(dct["x"], dct["y"])
            else:
                raise json.decoder.JSONDecodeError(f"""Unknown __type {dct["__type"]}""")
        return dct


class MessageEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ECPoint):
            return {
                "__type": "ECPoint",
                "x": obj.x,
                "y": obj.y
            }
        return json.JSONEncoder.default(self, obj)


"""
rooms:
{
    <room_name>: {
        name: string,
        ids_allowed: [<id>, ...],
        role_restrictions: {<id>: <role>, ...},
        ownership_type: "creator"|"members",
        creator: <id>,
        members: {
            <id>: conn_data = {
                client_id: <id>,
                client_id_escaped: <escaped id>
                addr_str: <ip>:<port>,
                addr: <addr>,
                authorized: True|False,
                socket: Socket,
                rooms: Set{<room name>, ...},
                inb: b"",
                outb: b""
            },
            ...
        },
        password: password|"",
        crs: {
            <variable_name>: value,
            ...
        },
        setup: {
            <param_name>: value,
            ...
        },
        proof: {
            <variable_name>: value,
            ...
        },
        verification_results: {
            <role@id>: "Success"|"Failure: <msg>",
            ...
        },
        inspection_results: {
            <role@id>: "Success"|"Failure: <msg>",
            ...
        },
        inspection: {
            <sender_role@sender_id:receiver_role:variable_name>: value,
            ...
        },
        variable_meta: {
            <sender_role@sender_id:receiver_role:variable_name>: {
                cost: <bits (int)>|"group"|"scalar"
            },
            ...
        },
        external_keys: {
            <key(variable)_name>: set{<allowed_receiver_role>, ...},
            ...
        },
        allowed_external_ids: {"last_contact": time},
        allowed_external_ids_lock: threading.Lock(),
        events: {
            room_changed: threading.Event
        },
        time_to_live: <number of seconds>,
        enable_man_in_the_middle: True|False
    }
}
"""
rooms = {}
rooms_changed_event = threading.Event()
"""
{
    <room name>: [
        (<timeout timestamp>, <meta>),
        ...
    ]
}
"""
rooms_creation_awaited = {}

"""
{
    <room name>: <remove timestamp>
}
"""
rooms_on_timeout = {}
rooms_on_timeout_lock = threading.Lock()

"""
{
    <id>: conn_data = {...},
    ...
}
"""
authorized_clients = {}
authorized_clients_external_ids_lock = threading.Lock()


def to_addr_str(addr):
    return addr[0] + ":" + str(addr[1])


def escape_colons(s, escape_character="\\"):
    return s.replace(":", escape_character + ":")


def escape_ats(s, escape_character="\\"):
    return s.replace("@", escape_character + "@")


def escape_colons_and_ats(s, escape_character="\\"):
    return s.replace("@", escape_character + "@").replace(":", escape_character + ":")


def unescape_colons(s, escape_character="\\"):
    return s.replace(escape_character + ":", ":")


def unescape_ats(s, escape_character="\\"):
    return s.replace(escape_character + "@", "@")


def unescape_colons_and_ats(s, escape_character="\\"):
    return s.replace(escape_character + "@", "@").replace(escape_character + ":", ":")


def parse_msg_data(meta, conn_data):
    if "data_parsed" in meta:
        if meta["valid"]:
            return meta["data_parsed"]
    parsed = {}
    data_format = meta["data_format"]
    msg_data_string = meta["data"]
    msg = meta["msg"]
    if data_format == "json":
        try:
            # print(f"Debug: Trying to decode json from {conn_data.client_id}: {msg_data_string}")
            parsed = json.loads(msg_data_string, cls=MessageDecoder)
            meta["valid"] = True
        except json.decoder.JSONDecodeError as e:
            meta["valid"] = False
            meta["__error__"] = f"Parsing failed: {str(e)}"
            print(f"Error: Received message {msg_data_string} from {conn_data.client_id} with malformed data: {str(e)}")
            return parsed
    else:
        print(f"Error: Received message with unknown data format {data_format} (only known format is json): {msg.strip()}")
        meta["valid"] = False
        meta["__error__"] = f"Parsing failed: Unknown data format {data_format}"
        return parsed
    return parsed


def parse_split_escaped_string(s, split_character, escape_character, max_parts=0, additional_escaped_characters=[]):
    parts = []
    part = ""
    part_start = 0
    i = 0
    while i < len(s):
        if s[i] == escape_character and i+1 < len(s) and (s[i+1] == escape_character or s[i+1] == split_character or s[i+1] in additional_escaped_characters):
            part += s[part_start:i]
            part_start = i+1
            i = i+2
        elif s[i] == split_character:
            part += s[part_start:i]
            parts.append(part)
            part = ""
            part_start = i+1
            if max_parts > 0 and len(parts) == max_parts - 1:
                break
            i = i+1
        else:
            i = i+1
    part += s[part_start:]
    parts.append(part)
    return parts


def parse_msg_meta(msg, conn_data):
    parsed = {}
    meta = {
        "msg": msg,
        "valid": False
    }
    # 5 parts: sender_role@sender_id, receiver_role@receiver_id, room, data_format, data
    msg_parts = parse_split_escaped_string(msg, ":", "\\", 5)
    if msg_parts[-1].endswith("\n"):  # TODO: when escaping \n introduced, remove this part
        msg_parts[-1] = msg_parts[-1][:-1]
    if len(msg_parts) != 5:
        print(f"Error: Received malformed message from {conn_data.addr_str} (expecting 5 parts separated by ':'): {msg.strip()}")
        meta["__error__"] = "Parsing failed: Expecting 5 parts separated by ':'"
        return meta
    # sender_role@sender_id
    sender_role_at_id_escaped = escape_colons(msg_parts[0])
    sender_parts = parse_split_escaped_string(msg_parts[0], "@", "\\")
    if len(sender_parts) > 2:
        print(f"Error: Received malformed message from {conn_data.addr_str} (expecting 2 sender parts separated by '@'): {msg.strip()}")
        meta["__error__"] = "Parsing failed: Expecting 2 sender parts separated by '@'"
        return meta
    if len(sender_parts) == 2:
        sender_role = sender_parts[0]
        sender_id = sender_parts[1]
    elif len(sender_parts) == 1:
        sender_role = sender_parts[0]
        sender_id = ""
    else:
        print(f"Assertion failure: len(sender_parts) > 0: sender_parts={sender_parts}")
        meta["__error__"] = "Parsing failed: Assertion failure"
        return meta
    meta["sender_role_at_id_escaped"] = sender_role_at_id_escaped
    meta["sender_role"] = sender_role
    meta["sender_id"] = sender_id
    if conn_data.authorized and meta["sender_id"] and conn_data.client_id != meta["sender_id"]:
        print(f"""Error: Received message where sender_id ({meta["sender_id"]}) does not match id of authorized client id ({conn_data.client_id}) the message was sent from""")
        meta["__error__"] = f"Parsing failed: sender id does not match id of authorized client ({conn_data.client_id})"
        return meta
    # receiver_role@receiver_id
    receiver_role_at_id_escaped = msg_parts[1]
    receiver_parts = parse_split_escaped_string(msg_parts[1], "@", "\\")
    if len(receiver_parts) > 2:
        print(f"Error: Received malformed message from {conn_data.addr_str} (expecting 2 receiver parts separated by '@'): {msg.strip()}")
        meta["__error__"] = "Parsing failed: Expecting 2 receiver parts separated by '@'"
        return meta
    if len(receiver_parts) == 2:
        receiver_role = receiver_parts[0]
        receiver_id = receiver_parts[1]
    elif len(receiver_parts) == 1:
        receiver_role = receiver_parts[0]
        receiver_id = ""
    else:
        print(f"Assertion failure: len(receiver_parts) > 0: receiver_parts={receiver_parts}")
        meta["__error__"] = "Parsing failed: Assertion failure"
        return meta
    meta["receiver_role_at_id_escaped"] = receiver_role_at_id_escaped
    meta["receiver_role"] = receiver_role
    meta["receiver_id"] = receiver_id
    # room
    room = msg_parts[2]
    meta["room"] = room
    meta["room_escaped"] = escape_colons(room)
    # data_format
    data_format = msg_parts[3]
    meta["data_format"] = data_format
    # data
    msg_data = msg_parts[4]
    meta["data"] = msg_data

    meta["valid"] = True
    return meta


def process_msg(meta, conn_data):
    # print(f"Router: Info: process_msg: {msg.strip()}")
    # sender_role@sender_id (escaped)
    sender_role_at_id_escaped = meta["sender_role_at_id_escaped"]
    def parsing_failed_response(responder_role_escaped="Router"):
        obj = {
            "__parsing__": meta,
            "status": "error",
            "msg": meta["__error__"] if "__error__" in meta else "Parsing error"
        }
        conn_data.socket.sendall(f"""{responder_role_escaped}:{sender_role_at_id_escaped}::json:{json.dumps(obj, cls=MessageEncoder)}\n""".encode())
        return False
    if not meta["valid"]:
        return parsing_failed_response()
    # sender_role, receiver_role, receiver_id, room
    sender_id = conn_data.client_id
    sender_role = meta["sender_role"]
    receiver_role_at_id_escaped = meta["receiver_role_at_id_escaped"]
    receiver_role = meta["receiver_role"]
    receiver_id = meta["receiver_id"]
    room = meta["room"]
    room_escaped = meta["room_escaped"]
    msg = meta["msg"]
    def response_helper(subject, response_msg, status="error", success=False, data="", responder_role_escaped="Router"):
        if subject == "__status__":
            obj = {
                "__status__": status,
                "msg": response_msg
            }
        else:
            obj = {
                subject: data,
                "status": status,
                "msg": response_msg
            }
        if status == "success":
            print(f"Router: Info: {subject} ({status}): {response_msg} (Message {msg} from {sender_id})")
        else:
            print(f"Router: {status}: {subject}: {response_msg} on message from {sender_id}")
        response_helper_msg = f"{responder_role_escaped}:{sender_role_at_id_escaped}:{room_escaped}:json:{json.dumps(obj, cls=MessageEncoder)}\n"
        try:
            conn_data.socket.sendall(response_helper_msg.encode())
        except Exception as e:
            print(f"response_helper: Error occurred sending message {response_helper_msg}{str(e)}")
        return success
    def response_room_info(room_info):
        variable_meta = room_info["variable_meta"]
        return {
            "ownership_type": room_info["ownership_type"],
            "creator": room_info["creator"],
            "members": list(room_info["members"].keys()),
            "role_restrictions": room_info["role_restrictions"],
            "crs": room_info["crs"],
            "proof": room_info["proof"],
            "variable_meta": {name: variable_meta[name] for name in room_info["proof"] if name in variable_meta}
        }
    def notify_if_room_complete(room_info):
        members = room_info["members"]
        if len(members) == len(room_info["ids_allowed"]):
            for member_id in members:
                members[member_id].socket.sendall(f"""Router:AllMembers:{room_escaped}:json:{json.dumps({
                    "__room_complete__": {
                        "members": list(room_info["members"].keys())
                    }
                }, cls=MessageEncoder)}\n""".encode())
    # sanity checks
    if not sender_id in authorized_clients:
        print(f"Router: Assertion Failure: process_msg: expecting client's id {sender_id} to be registered in <authorized_clients>: {(meta, msg_data)}")
        return False
    if receiver_id and (receiver_role == "CRS" or receiver_role == "AllMembers"):
        return response_helper("__status__", f"No receiver id must be specified if receiver role is '{receiver_role}'. Ignoring message {msg}")
    if sender_role == "Router" or sender_role == "Inspector":
        return response_helper("__status__", f"Sender role must not be 'Router' or 'Inspector'")    
    # handle receiver role 'Router' first
    if receiver_role == "Router":
        msg_data = parse_msg_data(meta, conn_data)
        if not meta["valid"]:
            return parsing_failed_response()
        # check if authorization is requested - always respond with success as process_msg is only called for authorized clients
        if "__authorize__" in msg_data:
            conn_data.socket.sendall(f"""Router:{sender_role_at_id_escaped}::json:{json.dumps({
                "__authorize__": "success",
                "status": "success",
                "msg": "Ignoring authorization request. Already authorized"
            }, cls=MessageEncoder)}\n""".encode())
            return True
        if "__leave_room__" in msg_data:
            if not room in conn_data.rooms or not room in rooms:
                conn_data.rooms.discard(room)
                return response_helper("__leave_room__", f"Info: Not a member of room '{room}'", "success", True, True)
            room_info = conn_data.rooms.pop(room)
            conn_data.socket.sendall(f"""Router:{sender_role_at_id_escaped}:{room_escaped}:json:{json.dumps({
                "__leave_room__": True,
                "status": "success",
                "msg": f"Success: Room '{room}' left"
            }, cls=MessageEncoder)}\n""".encode())
            members = room_info["members"]
            members.pop(sender_id)
            for member_id in members:
                id_conn_data = members[member_id]
                if room in id_conn_data.rooms:
                    id_conn_data.socket.sendall(f"""Router:@{id_conn_data.client_id_escaped}:{room_escaped}:json:{json.dumps({
                        "__member_left__": sender_id
                    }, cls=MessageEncoder)}\n""".encode())
            return True
        if "__delete_room__" in msg_data:
            if not room in rooms:
                conn_data.rooms.discard(room)
                return response_helper("__delete_room__", f"Info: Room '{room}' does not exist", "success", True, True)
            room_info = rooms[room]
            ownership_type = room_info["ownership_type"]
            if ownership_type != "creator":
                return response_helper("__delete_room__", f"Deleting room '{room}' is not supported for ownership type '{ownership_type}'")
            if room_info["creator"] != sender_id:
                return response_helper("__delete_room__", f"Only creator can delete room '{room}'")
            rooms.pop(room)
            members = room_info["members"]
            if sender_id in members:
                members.pop(sender_id)
            if room in conn_data.rooms:
                conn_data.rooms.discard(room)
            for member_id in members:
                id_conn_data = members[member_id]
                if room in id_conn_data.rooms:
                    id_conn_data.rooms.discard(room)
                    id_conn_data.socket.sendall(f"""Router:@{id_conn_data.client_id_escaped}:{room_escaped}:json:{json.dumps({
                        "__room_deleted__": room,
                        "msg": f"Room {room} has been deleted by its creator '{sender_id}'"
                    }, cls=MessageEncoder)}\nRouter:@{member_id}:{room_escaped}:json:{json.dumps({
                        "__leave_room__": room,
                        "msg": f"Room {room} deleted. Forced to leave room"
                    }, cls=MessageEncoder)}\n""".encode())
            conn_data.socket.sendall(f"""Router:{sender_role_at_id_escaped}:{room_escaped}:json:{json.dumps({
                "__delete_room__": room,
                "status": "success",
                "msg": f"Success: Room '{room}' deleted"
            }, cls=MessageEncoder)}\n""".encode())
            print(f"Router: Info: Room {room} deleted by {sender_id}")
            return True
        if "__join_room__" in msg_data:
            action_data = msg_data["__join_room__"]
            if room == "":
                return response_helper("__join_room__", f"Joining room {room} failed. Room name must not be empty")
            if not room in rooms:
                create_if_non_existing = "create_if_non_existing" in action_data and action_data["create_if_non_existing"]
                wait_if_non_existing = False
                if "wait_if_non_existing" in action_data:
                    wait_if_non_existing = action_data.pop("wait_if_non_existing")
                if create_if_non_existing:
                    if wait_if_non_existing:
                        return response_helper("__join_room__", f"Joining room {room} failed. Must not set both 'create_if_non_existing' and 'wait_if_non_existing' flags at the same time")
                    else:
                        pass  # will continue and create room
                else:
                    if wait_if_non_existing:
                        wait_at_least = 600  # wait at least 10 minutes
                        if isinstance(wait_if_non_existing, dict):
                            if "timeout" in wait_if_non_existing:
                                wait_at_least = min(wait_if_non_existing["timeout"], wait_at_least)
                        timeout_timestamp = time.time() + wait_at_least
                        if not room in rooms_creation_awaited:
                            rooms_creation_awaited[room] = []
                        rooms_creation_awaited[room].append((timeout_timestamp, meta))
                        print(f"Router: Debug: '{sender_id}' is awaiting to join room '{room}' ...")
                        # every time a new room is created, rooms_creation_awaited is checked
                        return True
                    else:
                        return response_helper("__join_room__", f"Joining room {room} failed. Does not exist")
            # room password
            room_password = ""
            if "password" in action_data:
                room_password = action_data["password"]
            # case room exists:
            if room in rooms:  # no need to create room, simply try joining
                room_info = rooms[room]
                if not sender_id in room_info["ids_allowed"]:
                    return response_helper("__join_room__", f"""Joining room {room} failed. {sender_id} is not in list of allowed ids: {room_info["ids_allowed"]}""")
                # check password
                mismatch_msg = ""
                if room_password != room_info["password"]:
                    mismatch_msg = f"Joining room {room} failed. Wrong password"
                # check ownership_type, creator, ids_allowed, crs, time_to_live, enable_man_in_the_middle
                elif "ownership_type" in action_data and action_data["ownership_type"] != room_info["ownership_type"]:
                    mismatch_msg = f"""Joining room {room} failed. Ownership type '{room_info["ownership_type"]}' does not match requested '{action_data["ownership_type"]}'"""
                elif "creator" in action_data and action_data["creator"] != room_info["creator"]:
                    mismatch_msg = f"""Joining room {room} failed. Creator '{room_info["creator"]}' does not match requested '{action_data["creator"]}'"""
                elif "ids_allowed" in action_data and {sender_id}.union(action_data["ids_allowed"]) != room_info["ids_allowed"]:
                    mismatch_msg = f"""Joining room {room} failed. Allowed IDs {room_info["ids_allowed"]} do not match requested {action_data["ids_allowed"]}"""
                elif "role_restrictions" in action_data and action_data["role_restrictions"] != room_info["role_restrictions"]:
                    mismatch_msg = f"""Joining room {room} failed. Role restrictions {room_info["role_restrictions"]} do not match requested '{action_data["role_restrictions"]}'"""
                elif "crs" in action_data and action_data["crs"] != room_info["crs"]:
                    mismatch_msg = f"""Joining room {room} failed. CRS '{room_info["crs"]}' does not match requested '{action_data["crs"]}'"""
                elif "external_keys" in action_data:
                    action_external_keys = set(action_data["external_keys"]).union({"__get_public_room_info__"})
                    if action_external_keys != room_info["external_keys"]:
                        mismatch_msg = f"""Joining room {room} failed. external_keys '{room_info["external_keys"]}' does not match requested '{action_external_keys}'"""
                elif "time_to_live" in action_data and action_data["time_to_live"] != room_info["time_to_live"]:
                    mismatch_msg = f"""Joining room {room} failed. time_to_live '{room_info["time_to_live"]}' does not match requested '{action_data["time_to_live"]}'"""
                elif "enable_man_in_the_middle" in action_data and action_data["enable_man_in_the_middle"] != room_info["enable_man_in_the_middle"]:
                    mismatch_msg = f"""Joining room {room} failed. enable_man_in_the_middle '{room_info["enable_man_in_the_middle"]}' does not match requested '{action_data["enable_man_in_the_middle"]}'"""
                members = room_info["members"]
                if not mismatch_msg:
                    # join room
                    # check role restrictions
                    if sender_id in room_info["role_restrictions"] and room_info["role_restrictions"][sender_id] != "":
                        required_role = room_info["role_restrictions"][sender_id]
                        if not sender_role:
                            return response_helper("__join_room__", f"Joining room {room} failed. Role restriction '{required_role}' can not be fulfilled because sender role was not provided")
                        if sender_role != required_role:
                            return response_helper("__join_room__", f"Joining room {room} failed. Role restriction '{required_role}' not fulfilled with sender role {sender_role}")
                    # all requirements are fulfilled
                    # add room to rooms list in connection data
                    conn_data.rooms.add(room)
                    # check if already member of room
                    if sender_id in members:
                        response_helper("__join_room__", f"Info: Already member of room '{room}'", "success", True, response_room_info(room_info))
                        if len(members) == len(room_info["ids_allowed"]):
                            # TODO after reconnect: got error Bad File Descriptor on socket on some tests -- TODO: is the socket being updated after reconnect
                            members[sender_id].socket.sendall(f"""Router:{sender_role_at_id_escaped}:{room_escaped}:json:{json.dumps({
                                "__room_complete__": {
                                    "members": list(room_info["members"].keys())
                                }
                            }, cls=MessageEncoder)}\n""".encode())
                        return True
                    # join room
                    members[sender_id] = conn_data
                    with rooms_on_timeout_lock:
                        if room in rooms_on_timeout:
                            del rooms_on_timeout[room]
                    response_helper("__join_room__", f"Joined room '{room}'", "success", True, response_room_info(room_info))
                    room_info["events"]["room_changed"].set()
                    # notify current members about new member
                    for member_id in members:
                        if member_id != sender_id:
                            members[member_id].socket.sendall(f"""Router:AllMembers:{room_escaped}:json:{json.dumps({
                                "__member_joined__": sender_id
                            }, cls=MessageEncoder)}\n""".encode())
                    # if room is complete, notify all members
                    notify_if_room_complete(room_info)
                    return True
                # in case of configuration mismatch
                # send error if not (sender is creator and room contains no other members)
                if not (sender_id == room_info["creator"] and (len(members) == 0 or sender_id in members)):
                    return response_helper("__join_room__", mismatch_msg)
                # else: delete room and create new
                rooms.pop(room)
                if sender_id in members:
                    members.pop(sender_id)
                if room in conn_data.rooms:
                    conn_data.rooms.discard(room)
            # else: if room does not exist OR: empty room has just been deleted because of configuration mismatch
            # create room
            ownership_type = "members"  # default
            if "ownership_type" in action_data:
                ownership_type = action_data["ownership_type"]
                if ownership_type != "creator" and ownership_type != "members":
                    return response_helper("__join_room__", f"Creating room {room} failed. Invalid ownership_type {ownership_type}.")
            ids_allowed = {sender_id}  # default
            if "ids_allowed" in action_data:
                ids_allowed = ids_allowed.union(action_data["ids_allowed"])
            role_restrictions = {}
            if "role_restrictions" in action_data:
                role_restrictions = action_data["role_restrictions"]
                if sender_id in role_restrictions and sender_role and sender_role != role_restrictions[sender_id]:
                    return response_helper("__join_room__", f"Creating room {room} failed. Creator can not fulfill rol restriction on his own id: {role_restrictions[sender_id]}")
            crs = {}  # default: empty CRS
            if "crs" in action_data:
                crs = action_data["crs"]
            external_keys = set({"__get_public_room_info__"})
            if "external_keys" in action_data:
                external_keys = external_keys.union(action_data["external_keys"])
            time_to_live = 86400  # default: 1 day
            if "time_to_live" in action_data:
                time_to_live = action_data["time_to_live"]
            enable_man_in_the_middle = False  # default
            if "enable_man_in_the_middle" in action_data:
                enable_man_in_the_middle = action_data["enable_man_in_the_middle"]
            room_info = {
                "name": room,
                "ids_allowed": ids_allowed,
                "role_restrictions": role_restrictions,
                "ownership_type": ownership_type,
                "creator": sender_id,
                "members": {
                    sender_id: conn_data
                },
                "password": room_password,
                "crs": crs,
                "setup": {},
                "proof": {},
                "verification_results": {},
                "inspection_results": {},
                "inspection": {},
                "variable_meta": {},
                "external_keys": external_keys,
                "allowed_external_ids": dict(),
                "allowed_external_ids_lock": threading.Lock(),
                "events": {
                    "room_changed": threading.Event()
                },
                "time_to_live": time_to_live,
                "enable_man_in_the_middle": enable_man_in_the_middle
            }
            rooms[room] = room_info
            conn_data.rooms.add(room)  # add room to rooms list in connection data
            response_helper("__join_room__", f"Created and joined room '{room}'", "success", True, response_room_info(room_info))
            notify_if_room_complete(room_info)
            # trigger everyone that is waiting for the room
            rooms_changed_event.set()
            if room in rooms_creation_awaited:
                for wait_info in rooms_creation_awaited.pop(room):
                    timeout_timestamp, wait_meta = wait_info
                    wait_id = wait_meta["sender_id"]
                    if not wait_id in authorized_clients:
                        # not authorized/connected any more - don't responed
                        continue
                    if timeout_timestamp < time.time():
                        # timeout
                        subject = "__join_room__"
                        status = "error"
                        response_msg = f"Joining room {room} failed. Timeout on waiting for it to be created"
                        obj = {
                            subject: "",
                            "status": status,
                            "msg": response_msg
                        }
                        print(f"""Router: Info: Timeout for {wait_id} on waiting for room to be created""")
                        conn_data.socket.sendall(f"Router:{sender_role_at_id_escaped}:{room_escaped}:json:{json.dumps(obj, cls=MessageEncoder)}\n".encode())
                        continue
                    wait_conn_data = authorized_clients[wait_id]
                    process_msg(wait_meta, wait_conn_data)
            return True
        # end if "__join_room__" in msg_data
        else:
            return response_helper("__status__", f"No known router action for message {msg}")
    # end if receiver_role == "Router"
    # room
    if room == "":
        return response_helper("__parsing__", f"Need room to be specified")
    elif not room in rooms:
        return response_helper("__status__", f"Room {room} does not exist")
    room_info = rooms[room]
    room_changed = room_info["events"]["room_changed"]
    def add_variables_to_the_room(target, with_suffix=False):
        msg_data = parse_msg_data(meta, conn_data)
        if not meta["valid"]:
            return parsing_failed_response("Inspector")
        if not isinstance(msg_data, dict):
            conn_data.socket.sendall(f"""Inspector:{sender_role_at_id_escaped}:{room_escaped}:json:{json.dumps({
                "__status__": "warning",
                "msg": f"Received message with data payload that is not an object. Unable to add variables to room '{room}'"
            }, cls=MessageEncoder)}\n""".encode())
            return False
        changed = False
        def set_cost(var_key, var_key_with_suffix, cost):
            if type(cost) == str:
                if cost != "group" and cost != "scalar":
                    print(f"Inspector: Warning: Room {room}/{target}/{var_key}: invalid cost specification: '{cost}'")
                    return
            elif type(cost) == int:
                if cost < 0:
                    print(f"Inspector: Warning: Room {room}/{target}/{var_key}: invalid negative cost: {cost}")
                    return
            else:
                print(f"Inspector: Warning: Room {room}/{target}/{var_key}: unknown cost type: {type(cost)}")
                return
            if not var_key_with_suffix in room_info["variable_meta"]:
                room_info["variable_meta"][var_key_with_suffix] = {
                    "cost": cost
                }
            else:
                room_info["variable_meta"][var_key_with_suffix]["cost"] = cost
        if "_verification_result_" in msg_data:
            sender_role_at_id = unescape_colons(sender_role_at_id_escaped)
            verification_result = msg_data["_verification_result_"]
            def verification_status_to_msg(status):
                if status == "success":
                    return "Verification successful"
                elif status == "fail":
                    return "Verification failed"
                else:
                    return status
            if type(verification_result) == str:
                room_info["verification_results"][sender_role_at_id] = verification_status_to_msg(verification_result)
            elif type(verification_result) == dict:
                msg = ""
                if "status" in verification_result:
                    msg = verification_status_to_msg(verification_result["status"])
                if "msg" in verification_result:
                    if msg:
                        msg += ": "
                    msg += verification_result["msg"]
                room_info["verification_results"][sender_role_at_id] = msg
            else:
                room_info["verification_results"][sender_role_at_id] = str(verification_result)
            changed = True
        if "_inspection_result_" in msg_data:
            sender_role_at_id = unescape_colons(sender_role_at_id_escaped)
            inspection_result = msg_data["_inspection_result_"]
            def inspection_status_to_msg(status):
                if status == "success":
                    return "Inspection successful"
                elif status == "fail":
                    return "Inspection failed"
                else:
                    return status
            if type(inspection_result) == str:
                room_info["inspection_results"][sender_role_at_id] = inspection_status_to_msg(inspection_result)
            elif type(inspection_result) == dict:
                msg = ""
                if "status" in inspection_result:
                    msg = inspection_status_to_msg(inspection_result["status"])
                if "msg" in inspection_result:
                    if msg:
                        msg += ": "
                    msg += inspection_result["msg"]
                room_info["inspection_results"][sender_role_at_id] = msg
            else:
                room_info["inspection_results"][sender_role_at_id] = str(inspection_result)
            changed = True
        for var_name in msg_data:
            var_key_with_suffix = escape_colons(var_name) + ":" + sender_role_at_id_escaped + ":" + receiver_role_at_id_escaped
            if not var_name.startswith("_"):
                # invalidate (delete) verification results when a new value is added to the proof
                if target == "Proof":
                    room_info["verification_results"] = dict()
                    room_info["inspection_results"] = dict()
                if with_suffix:
                    var_key = var_key_with_suffix
                else:
                    var_key = var_name
                var_value = msg_data[var_name]
                print(f"Router: Debug: Adding variable {var_key} with value {var_value} to {room}/{target}")
                if var_key in room_info[target]:
                    prev_var_value = room_info[target][var_key]
                    if str(prev_var_value) != str(var_value):
                        print(f"Router: Info: Overriding value {prev_var_value} of {var_key} with {var_value} from {sender_role} in {room}/{target}")
                        changed = True
                else:
                    changed = True
                if var_value == None:
                    room_info[target].pop(var_key)
                else:
                    room_info[target][var_key] = var_value
                    if "_cost" in msg_data:
                        cost = msg_data["_cost"]
                        if type(cost) == dict:
                            if var_name in cost:
                                set_cost(var_key, var_key_with_suffix, cost[var_name])
                        else:
                            set_cost(var_key, var_key_with_suffix, cost)
        if changed:
            room_changed.set()
        return True
    # check sender: member of room? / external_keys?
    if not sender_id in room_info["members"]:
        # sender is not member of room
        # he is only allowed to send messages with keys listed in the room's external_keys
        msg_data = parse_msg_data(meta, conn_data)
        if not meta["valid"]:
            return parsing_failed_response()
        # check room password
        password_check_required = False
        password = ""
        if "__room_password__" in msg_data:
            password = msg_data.pop("__room_password__")
            password_check_required = True
        if not sender_id in room_info["allowed_external_ids"]:
            password_check_required = True
        if password_check_required and password != room_info["password"]:
            return response_helper("__status__", f"Sending message to room '{room}' failed. Wrong password")
        with room_info["allowed_external_ids_lock"]:
            room_info["allowed_external_ids"][sender_id] = {
                "last_contact": time.time()
            }
        # Let Inspector accept all
        if receiver_role == "Inspector":
            if "__get_public_room_info__" in msg_data:
                conn_data.socket.sendall(f"""Inspector:{sender_role_at_id_escaped}::json:{json.dumps({
                    "status": "success",
                    "__get_public_room_info__": response_room_info(room_info)
                }, cls=MessageEncoder)}\n""".encode())
                return True
            else:
                return add_variables_to_the_room("inspection", ":" + sender_role_at_id_escaped + ":" + receiver_role_at_id_escaped)
        # check for and handle external_keys
        for key_name in msg_data.keys():
            if not key_name in room_info["external_keys"]:
                return response_helper("__status__", f"Sending message to room '{room}' failed. Key '{key_name}' not in list of allowed external keys")
        if not receiver_id:
            if len(room_info["members"]) == 0:
                return response_helper("__status__", f"Sending message failed: no members in room (any more)")
            if len(room_info["members"]) == 1:
                receiver_id = list(room_info["members"].keys())[0]
            else:
                return response_helper("__status__", f"Sending message failed: need to specify receiver ID if room has more than one member")
        if not receiver_id in room_info["members"] or not receiver_id in authorized_clients:
            return response_helper("__status__", f"Sending message failed: '{receiver_id}' not an authorized member of room '{room}'")
        add_variables_to_the_room("proof", ":" + sender_role_at_id_escaped + ":" + receiver_role_at_id_escaped)
        # send message
        authorized_clients[receiver_id].socket.sendall(msg.encode())
        return True
    # handle receiver role 'Inspector' second
    if receiver_role == "Inspector":
        msg_data = parse_msg_data(meta, conn_data)
        if not meta["valid"]:
            return parsing_failed_response("Inspector")
        if "__get_public_room_info__" in msg_data:
            conn_data.socket.sendall(f"""Inspector:{sender_role_at_id_escaped}::json:{json.dumps({
                "status": "success",
                "__get_public_room_info__": response_room_info(room_info)
            }, cls=MessageEncoder)}\n""".encode())
            return True
        elif "__clear_inspection__" in msg_data:
            def clear_inspection():
                room_info["crs"] = {}
                room_info["proof"] = {}
                room_info["inspection"] = {}
                room_changed.set()
                return response_helper("__clear_inspection__" ,f"Clearing values in {room} successful", "success", True, "", "Inspector")
            if room_info["ownership_type"] == "creator":
                if room_info["creator"] != sender_id:
                    return response_helper("__clear_inspection__", f"Could not clear values in {room} because {sender_id} is not its creator", "error", False, "", "Inspector")
                return clear_inspection()
            # else: room_info["ownership_type"] == "member"
            return clear_inspection()  # TODO: improvement possible: clear only when majority of members has sent a clear command
        elif "__setup__" in msg_data:
            if room_info["ownership_type"] == "creator":
                if room_info["creator"] != sender_id:
                    return response_helper("__setup__", f"Could not set setup values in {room} because {sender_id} is not its creator", "error", False, "", "Inspector")
                room_info["setup"] = msg_data["__setup__"]
                return True
            # else: room_info["ownership_type"] == "member"
            room_info["setup"] = msg_data["__setup__"]
            return True  # TODO: improvement possible: setup only when majority of members has sent the same setup command
        else:
            # add variables to room inspection, no other action
            return add_variables_to_the_room("inspection", ":" + sender_role_at_id_escaped + ":" + receiver_role_at_id_escaped)
    # end if receiver_role == "Inspector"
    # sender: Prover, InteractiveVerifier, Member, ID
    # receiver: CRS, Proof, Prover, InteractiveVerifier, AllMembers, ID
    # receiver_role
    if receiver_role == "CRS":
        return add_variables_to_the_room("crs")
    if receiver_role == "Proof":
        return add_variables_to_the_room("proof", ":" + sender_role_at_id_escaped + ":" + receiver_role_at_id_escaped)
    def check_and_send_to_receiver_id(receiver_id):
        if receiver_id in room_info["members"]:
            room_info["members"][receiver_id].socket.sendall(msg.encode())
        elif receiver_id in room_info["allowed_external_ids"]:
            if not receiver_id in authorized_clients:
                return response_helper("__status__", f"ID {receiver_id} is not authorized on routing server")
            with room_info["allowed_external_ids_lock"]:
                room_info["allowed_external_ids"][sender_id] = {
                    "last_contact": time.time()
                }
            authorized_clients[receiver_id].socket.sendall(msg.encode())
        else:
            return response_helper("__status__", f"ID {receiver_id} is not a member of room {room} or an allowed external ID")
        return True
    if receiver_role == "Prover" or receiver_role == "InteractiveVerifier":
        if not receiver_id:
            if len(room_info["members"]) != 2:
                return response_helper("__status__", f"Need to specify receiver id if number of room members does not equal 2")
            member_ids = list(room_info["members"].keys())
            if member_ids[0] == sender_id:
                receiver_id = member_ids[1]
            else:
                if member_ids[1] != sender_id:
                    return response_helper("__status__", f"Assertion failure: sender id {sender_id} must be room member")
                receiver_id = member_ids[0]
        if not check_and_send_to_receiver_id(receiver_id):
            return False
    elif receiver_role == "AllMembers":
        for member_id in room_info["members"]:
            if member_id == sender_id:
                continue
            room_info["members"][member_id].socket.sendall(msg.encode())
    else:
        if not check_and_send_to_receiver_id(receiver_id):
            return response_helper("__status__", f"Unknown receiver role '{receiver_role}' and unknown ID '{receiver_id}'")
    # finally, add variables sent to other room members to proof
    add_variables_to_the_room("proof", ":" + sender_role_at_id_escaped + ":" + receiver_role_at_id_escaped)
    return True


def authorize_client(meta, conn_data):
    print(f"Router: Info: authorize_client: {meta}")
    if not meta["valid"]:
        conn_data.authorized = False
        return False
    msg = meta["msg"]
    if not meta["sender_id"]:
        print(f"Router: Error: No sender_id provided by new client from {conn_data.addr_str}")
        conn_data.authorized = False
        return False
    client_id = meta["sender_id"]
    conn_data.client_id = client_id
    client_id_escaped = escape_colons_and_ats(client_id)
    conn_data.client_id_escaped = client_id_escaped
    if meta["receiver_role"] != "Router":
        print(f"""Router: Error: receiver_role of authorization message is expected to be 'Router' but it is '{meta["receiver_role"]}'""")
        conn_data.authorized = False
        return False
    msg_data = parse_msg_data(meta, conn_data)
    if not "__authorize__" in msg_data:
        print(f"Router: Warning: Client {client_id} from {conn_data.addr_str} can not authorize: __authorize__ missing")
        conn_data.authorized = False
        return False
    action_data = msg_data["__authorize__"]
    # check router password
    if router_connection_password:
        if "router_password" in action_data and action_data["router_password"] == router_connection_password:
            pass
        else:
            print(f"Router: Warning: Client {client_id} from {conn_data.addr_str} was not able to authorize")
            conn_data.authorized = False
            return False
    else:
        if "router_password" in action_data and action_data["router_password"]:
            print(f"Router: Debug: No password required. Ignoring router_password provided by {client_id}")
            pass
        else:
            pass
    # check connection password (specific to client_id)
    if conn_data.conn_password:
        if not "connection_password" in action_data or action_data["connection_password"] != conn_data.conn_password:
            print(f"Client {client_id} from {conn_data.addr_str} didn't provide correct connection_password for reconnection")
            conn_data.authorized = False
            conn_data.socket.sendall(f"""Router:@{client_id_escaped}::json:{json.dumps({
                "__authorize__": "error",
                "status": "error",
                "msg": "Authorization failed: Incorrect connection_password"
            }, cls=MessageEncoder)}\n""".encode())
            return False
    else:
        if "connection_password" in action_data:
            conn_data.conn_password = action_data["connection_password"]
    conn_data.authorized = True
    if client_id in authorized_clients:
        id_conn_data = authorized_clients[client_id]
        if id_conn_data.socket is conn_data.socket:
            return True
        print(f"Router: Info: Client {client_id} from {conn_data.addr_str} authorized with new connection. Closing old connection from {id_conn_data.addr_str}.")
        if conn_data.inb:
            print(f"Router: Info: incoming conn_data from old connection will be dropped: {conn_data.inb}")
        conn_data.rooms = id_conn_data.rooms
        conn_data.authorized = id_conn_data.authorized
        for room in conn_data.rooms:
            rooms[room]["members"][client_id] = conn_data
        try:  # TODO: fix/handle possible errors
            id_conn_data.client_id = -2  # indicate connection has been overridden
            sel.unregister(id_conn_data.socket)
            id_conn_data.socket.close()
        except Exception as e:
            print(f"Router: Warning: Error on closing socket of client {id_conn_data.client_id} from {id_conn_data.addr_str}: {str(e)}")
    else:
        print(f"Router: Info: Authorized client {client_id} from {conn_data.addr_str}")
    authorized_clients[client_id] = conn_data
    # print(f"Data structures:\nrooms=")
    # pp.pprint(rooms)
    # print(f"\nauthorized_clients=")
    # pp.pprint(authorized_clients)
    conn_data.socket.sendall(f"""Router:@{client_id_escaped}::json:{json.dumps({
        "__authorize__": "success",
        "status": "success",
        "msg": "Authorization successful"
    }, cls=MessageEncoder)}\n""".encode())
    return True


def accept_connection(sock):
    conn, addr = sock.accept()
    addr_str = to_addr_str(addr)
    print(f"Router: Info: Accepted connection from {addr_str}")
    conn.setblocking(False)
    conn_data = types.SimpleNamespace(addr=addr, addr_str=addr_str, inb=b"", outb=b"", authorized=False, client_id=-1, client_id_escaped=-1, socket=sock, rooms=set(), conn_password="", allowed_external_ids={})
    events = selectors.EVENT_READ
    sel.register(conn, events, data=conn_data)


def service_connection_read(sock, conn_data):
    conn_data.socket = sock
    recv_data = None
    try:
        recv_data = sock.recv(4096)
    except Exception as e:  # TimeoutError
        print(f"Router: Error on receiving conn_data on connection {conn_data.addr_str}: {e}")
    if not recv_data:
        print(f"Router: Info: Closing connection to {conn_data.addr_str}")
        if conn_data.client_id in authorized_clients:
            authorized_clients.pop(conn_data.client_id)
            print(f"Router: Debug: remove {conn_data.client_id} from authorized_clients, which now contains {authorized_clients.keys()}")
        if conn_data.client_id != -2:
            print(f"Router: Debug: remove {conn_data.client_id} from rooms ...")
            for room in conn_data.rooms:
                if not room in rooms:
                    continue
                room_info = rooms[room]
                if conn_data.client_id in room_info["members"]:
                    room_info["members"].pop(conn_data.client_id)  # TODO: possible improvement: send client disconnected to all members of group
                    print(f"Router: Info: remove {conn_data.client_id} from room '{room}'")
                if not room_info["members"]:
                    with rooms_on_timeout_lock:
                        rooms_on_timeout[room] = time.time() + room_info["time_to_live"]
        #if not sock is id_conn:
        #    print(f"Data structure corruption detected in variable <authorized_clients> on closing connection to client with id {conn_data.client_id} and expected address {to_addr_str(id_conn.getpeername())}")
        try:
            sel.unregister(sock)
            sock.close()
        except Exception as e:
            print(f"Router: Info: Exception occurred on closing socket {sock} ({conn_data.addr_str}): {e}")
        return
    if conn_data.client_id == -2:
        # connection no longer active
        print(f"Router: Info: Received conn_data on connection {conn_data} that is no longer active: {recv_data}")
        return
    prev_inb = False
    if conn_data.inb:
        prev_inb = True
    conn_data.inb += recv_data
    if not conn_data.authorized:
        print(f"Router: Info: Received conn_data {str(conn_data.inb)} on currently unauthorized connection {conn_data.addr_str}")
        msg_end = conn_data.inb.find(ord("\n"))
        if msg_end == -1:
            if not conn_data.authorized and len(conn_data.inb) > 2048:
                print(f"Router: Warning: Rejecting unauthorized connections that send messages larger than 2KiB. Closing connection to {conn_data.addr_str}.")
                sel.unregister(sock)
                sock.close()
                return
        try:
            msg = conn_data.inb[:msg_end+1].decode()
        except UnicodeDecodeError as err:
            print(f"Router: Warning: Client did send an invalid string ({err}). Closing connection to {conn_data.addr_str}")
            sel.unregister(sock)
            sock.close()
            return
        conn_data.inb = conn_data.inb[msg_end+1:]
        # need to authorize:
        msg_meta = parse_msg_meta(msg, conn_data)
        if authorize_client(msg_meta, conn_data):
            conn_data.authorized = True
        else:
            print(f"Router: Warning: Client was not able to authorize with message {msg.strip()}. Closing connection to {conn_data.addr_str}")
            sel.unregister(sock)
            sock.close()
            return
    # process message of authorized client
    while conn_data.inb:
        msg_end = conn_data.inb.find(ord("\n"))
        if msg_end == -1:
            print(f"Router: Debug: Partial message ending with {conn_data.inb.decode()} received from {conn_data.client_id} ({len(conn_data.inb)} bytes)")
            break
        try:
            msg = conn_data.inb[:msg_end+1].decode()
        except UnicodeDecodeError as e:
            print(f"Router: Error: Message received from {conn_data.client_id} could not be decoded as Unicode: {str(e)}")
            conn_data.inb = conn_data.inb[msg_end+1:]
            continue
        conn_data.inb = conn_data.inb[msg_end+1:]
        if prev_inb:
            print(f"Router: Debug: Partial message completed ({msg_end} bytes)")
            prev_inb = False
        meta = parse_msg_meta(msg, conn_data)
        process_msg(meta, conn_data)


# inspector

def get_web_room_data(room_info):
    return {
        "ownership_type": room_info["ownership_type"],
        "creator": room_info["creator"],
        "members": list(room_info["members"].keys()),
        "crs": {key: str(val) for key, val in room_info["crs"].items()},
        "setup": room_info["setup"],
        "proof": {key: str(val) for key, val in room_info["proof"].items()},
        "verification_results": room_info["verification_results"],
        "inspection_results": room_info["inspection_results"],
        "inspection": {key: str(val) for key, val in room_info["inspection"].items()},
        "variable_meta": room_info["variable_meta"]
    }


app_server = None
def inspector_main():
    global app_server

    app = Flask(__name__)
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["APPLICATION_ROOT"] = inspector_application_root
    bp = Blueprint("prefixed", __name__, template_folder="templates");

    @bp.route("/")
    def i_root():
        return render_template("index.html", rooms=rooms, base_http_url=inspector_url_http, base_ws_url=inspector_url_ws)

    @bp.route("/<room_enc>")
    def room(room_enc):
        room = urllib.parse.unquote(room_enc)
        if not room in rooms:
            return render_template("404-room.html", room=room, room_enc=room_enc, base_http_url=inspector_url_http, base_ws_url=inspector_url_ws), 404
        room_info = rooms[room]
        return render_template("room.html", room=room, base_http_url=inspector_url_http, base_ws_url=inspector_url_ws)

    @bp.route("/<room_enc>/wait")
    def room_wait(room_enc):
        room = urllib.parse.unquote(room_enc)
        if room in rooms:
            return redirect("../", code=302)
        return render_template("room-wait.html", room=room, room_enc=room_enc, base_http_url=inspector_url_http, base_ws_url=inspector_url_ws)

    @bp.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

    @bp.route("/rooms", websocket=True)
    def sock_rooms():
        websocket = simple_websocket.Server(request.environ)
        print(f"Inspector: Info: Connected websocket {websocket} on /rooms")
        changed = True
        try:
            while websocket.connected:
                if changed:
                    data_string = json.dumps(list(rooms.keys()))
                    # print(f"Inspector: Debug: Sending {data_string}")
                    websocket.send(data_string)
                changed = rooms_changed_event.wait(2.5)
                rooms_changed_event.clear()
            # print(f"Inspector: Debug: Disconnected websocket {websocket} on /rooms")
        except simple_websocket.ConnectionClosed:
            # print(f"Inspector: Debug: Disconnected websocket {websocket} on /rooms")
            pass
        return ""

    @bp.route("/inspect/<room_enc>", websocket=True)
    def sock_inspect_room(room_enc):
        room = urllib.parse.unquote(room_enc)
        websocket = simple_websocket.Server(request.environ)
        # print(f"Inspector: Debug: Connected websocket {websocket} on /inspect/{room}")
        room_info = rooms[room]
        room_changed = room_info["events"]["room_changed"]
        changed = True
        try:
            while websocket.connected:
                if changed:
                    websocket.send(json.dumps(get_web_room_data(room_info), cls=MessageEncoder))
                changed = room_changed.wait(2.5)  # possible improvement: producer thread for events + consumer thread that reacts on events with rate limiting and sends conn_data to active websockets (same improvement for ws://rooms)
                room_changed.clear()
            # print(f"Inspector: Debug: Disconnected websocket {websocket} on /inspect/{room}")
        except simple_websocket.ConnectionClosed:
            # print(f"Inspector: Debug: Disconnected websocket {websocket} on /inspect/{room}")
            pass
        return ""

    try:
        app_server = make_server(inspector_host, inspector_port, app, threaded=True)
    except (Exception, OSError) as e:
        print(f"Inspector: Error:  Starting web server failed: {str(e)}")
        return
    app_ctx = app.app_context()
    app_ctx.push()
    app.register_blueprint(bp, url_prefix=inspector_application_root)
    print(f"Inspector: Info: Listening on {(inspector_host, inspector_port)}")
    app_server.serve_forever()


# router

def router_main():
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lsock.bind((router_host, router_port))
    except OSError as e:
        print(f"Router: Error: OSError: {e}")
        time.sleep(5)
        if app_server:
            app_server.shutdown()
        inspector_thread.join()
        sys.exit(1)
    lsock.listen()
    print(f"Router: Info: Listening on {(router_host, router_port)}")
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)
    try:
        while True:
            events = sel.select()
            for key, mask in events:
                if key.data is None:
                    accept_connection(key.fileobj)
                else:
                    service_connection_read(key.fileobj, key.data)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.unregister(lsock)
        lsock.close()
        for client_id in authorized_clients:
            sock = authorized_clients[client_id].socket
            sel.unregister(sock)
            sock.close()
        sel.close()


# router - garbage collector for inactive rooms

gc_stop_event = threading.Event()

def router_gc():
    while True:
        now = time.time()
        # unused rooms
        with rooms_on_timeout_lock:
            for room in rooms_on_timeout:
                if rooms_on_timeout[room] <= now:
                    if room in rooms:
                        rooms.pop(room)
        # inactive external connections
        for room_name, room in rooms.items():
            with room["allowed_external_ids_lock"]:
                for external_id in list(room["allowed_external_ids"].keys()):
                    if room["allowed_external_ids"][external_id]["last_contact"] + 3600 <= now:
                        room["allowed_external_ids"].pop(external_id)
        if gc_stop_event.wait(300):
            break


# run router, router GC and inspector

inspector_thread = threading.Thread(target=inspector_main)
inspector_thread.start()

router_gc_thread = threading.Thread(target=router_gc)
router_gc_thread.start()

router_main()


print("Shutting down Router GC ...")
gc_stop_event.set()
print("Waiting for Router GC to shut down ...")
router_gc_thread.join()

print("Shutting down Inspector ...")
app_server.shutdown()
print("Waiting for Inspector to shut down ...")
inspector_thread.join()
