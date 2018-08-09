#!/usr/bin/env python3
"""
Interception proxy using mitmproxy (https://mitmproxy.org).
Communicates to NodeJS via websockets.
"""

import argparse
import asyncio
import queue
import json
import threading
import typing
import traceback
import sys
import struct
import websockets
from mitmproxy import ctx
from mitmproxy import http

def convert_headers_to_bytes(header_entry):
    """
    Converts a tuple of strings into a tuple of bytes.
    """
    return [bytes(header_entry[0], "utf8"), bytes(header_entry[1], "utf8")]

def convert_body_to_bytes(body):
    """
    Converts a HTTP request/response body into a list of numbers.
    """
    if body is None:
        return bytes()
    else:
        return body

def is_text_response(headers):
    if 'content-type' in headers:
        ct = headers['content-type'].lower()
        # Allow all application/ and text/ MIME types.
        return 'application' in ct or 'text' in ct or ct.strip() == ""
    return True

class WebSocketAdapter:
    """
    Relays HTTP/HTTPS requests to a websocket server.
    Enables using MITMProxy from outside of Python.
    """

    def websocket_thread(self):
        """
        Main function of the websocket thread. Runs the websocket event loop
        until MITMProxy shuts down.
        """
        self.worker_event_loop = asyncio.new_event_loop()
        self.worker_event_loop.run_until_complete(self.websocket_loop())

    def __init__(self):
        self.queue = queue.Queue()
        self.intercept_paths = frozenset([])
        self.only_intercept_text_files = False
        self.finished = False
        # Start websocket thread
        threading.Thread(target=self.websocket_thread).start()

    def load(self, loader):
        loader.add_option(
            "intercept", str, "",
            """
            A list of HTTP paths, delimited by a comma, to intercept and pass to Node without hitting the server.
            E.g.: /foo,/bar
            """
        )
        loader.add_option(
            name = "onlyInterceptTextFiles",
            typespec = bool,
            default = False,
            help = "If true, the plugin only intercepts text files and passes through other types of files",
        )
        return

    def configure(self, updates):
        if "intercept" in updates:
            self.intercept_paths = frozenset(ctx.options.intercept.split(","))
            #print("Intercept paths:")
            #print(self.intercept_paths)
        if "onlyInterceptTextFiles" in updates:
            self.only_intercept_text_files = ctx.options.onlyInterceptTextFiles
            #print("Only intercept text files:")
            #print(self.only_intercept_text_files)
        return

    def send_message(self, metadata, data1, data2):
        """
        Sends the given message on the WebSocket connection,
        and awaits a response. Metadata is a JSONable object,
        and data is bytes.
        """
        metadata_bytes = bytes(json.dumps(metadata), 'utf8')
        data1_size = len(data1)
        data2_size = len(data2)
        metadata_size = len(metadata_bytes)
        msg = struct.pack("<III" + str(metadata_size) + "s" +
                          str(data1_size) + "s" + str(data2_size) + "s",
                          metadata_size, data1_size, data2_size, metadata_bytes, data1, data2)
        obj = {
            'lock': threading.Condition(),
            'msg': msg,
            'response': None
        }
        # We use the lock to marry multithreading with asyncio.
        #print("acquiring lock")
        obj['lock'].acquire()
        #print("inserting into list")
        self.queue.put(obj)
        #print("waiting")
        obj['lock'].wait()
        #print("wait finished!")
        new_response = obj['response']
        if new_response is None:
            # Never got a response / an error occurred
            return None

        new_response_size = len(new_response)
        all_data = struct.unpack("<II" + str(new_response_size - 8) + "s", new_response)

        return (json.loads(all_data[2][0:all_data[0]]), all_data[2][all_data[0]:])

    def request(self, flow):
        """
        Intercepts an HTTP request. If the proxy is configured to intercept the path, then
        do so without sending to the server.
        """
        if flow.request.path in self.intercept_paths:
            request = flow.request
            message_response = self.send_message({
                'request': {
                    'method': request.method,
                    'url': request.url,
                    'headers': list(request.headers.items(True))
                },
                'response': {
                    'status_code': 200,
                    'headers': list()
                }
            }, convert_body_to_bytes(request.content), convert_body_to_bytes(None))
            if message_response is None:
                # No response received; making no modifications.
                return
            new_metadata = message_response[0]
            new_body = message_response[1]

            flow.response = http.HTTPResponse.make(
                new_metadata['status_code'],
                new_body,
                map(convert_headers_to_bytes, new_metadata['headers'])
            )
        return

    def responseheaders(self, flow):
        # Stream all non-text responses if only_intercept_text_files is enabled.
        # Do not stream intercepted paths.
        flow.response.stream = flow.request.path not in self.intercept_paths and self.only_intercept_text_files and not is_text_response(flow.response.headers)

    def response(self, flow):
        """
        Intercepts an HTTP response. Mutates its headers / body / status code / etc.
        """
        # Streaming responses are things we said to stream in responseheaders
        if flow.response.stream:
            return

        request = flow.request

        # Ignore intercepted paths
        if request.path in self.intercept_paths:
            return
        response = flow.response
        message_response = self.send_message({
            'request': {
                'method': request.method,
                'url': request.url,
                'headers': list(request.headers.items(True)),
            },
            'response': {
                'status_code': response.status_code,
                'headers': list(response.headers.items(True)),
            }
        }, convert_body_to_bytes(request.content), convert_body_to_bytes(response.content))

        if message_response is None:
            # No response received; making no modifications.
            return

        new_metadata = message_response[0]
        new_body = message_response[1]


        #print("Prepping response!")

        flow.response = http.HTTPResponse.make(
            new_metadata['status_code'],
            new_body,
            map(convert_headers_to_bytes, new_metadata['headers'])
        )
        return

    def done(self):
        """
        Called when MITMProxy is shutting down.
        """
        # Tell the WebSocket loop to stop processing events
        self.finished = True
        self.queue.put(None)
        return

    async def websocket_loop(self):
        """
        Processes messages from self.queue until mitmproxy shuts us down.
        """
        while not self.finished:
            try:
                async with websockets.connect('ws://localhost:8765', max_size = None) as websocket:
                    while True:
                        # Make sure connection is still live.
                        await websocket.ping()
                        try:
                            obj = self.queue.get(timeout=1)
                            if obj is None:
                                break
                            try:
                                obj['lock'].acquire()
                                await websocket.send(obj['msg'])
                                obj['response'] = await websocket.recv()
                            finally:
                                # Always remember to wake up other thread + release lock to avoid deadlocks
                                obj['lock'].notify()
                                obj['lock'].release()
                        except queue.Empty:
                            pass
            except websockets.exceptions.ConnectionClosed:
                # disconnected from server
                pass
            except BrokenPipeError:
                # Connect failed
                pass
            except IOError:
                # disconnected from server mis-transfer
                pass
            except:
                print("[mitmproxy-node plugin] Unexpected error:", sys.exc_info())
                traceback.print_exc(file=sys.stdout)

addons = [
    WebSocketAdapter()
]
