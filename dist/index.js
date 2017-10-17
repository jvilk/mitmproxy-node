"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const ws_1 = require("ws");
const child_process_1 = require("child_process");
const path_1 = require("path");
const url_1 = require("url");
const http_1 = require("http");
const https_1 = require("https");
const net_1 = require("net");
/**
 * Wait for the specified port to open.
 * @param port The port to watch for.
 * @param retries The number of times to retry before giving up. Defaults to 10.
 * @param interval The interval between retries, in milliseconds. Defaults to 500.
 */
function waitForPort(port, retries = 10, interval = 500) {
    return new Promise((resolve, reject) => {
        let retriesRemaining = retries;
        let retryInterval = interval;
        let timer = null;
        let socket = null;
        function clearTimerAndDestroySocket() {
            clearTimeout(timer);
            timer = null;
            if (socket)
                socket.destroy();
            socket = null;
        }
        function retry() {
            tryToConnect();
        }
        function tryToConnect() {
            clearTimerAndDestroySocket();
            if (--retriesRemaining < 0) {
                reject(new Error('out of retries'));
            }
            socket = net_1.createConnection(port, "localhost", function () {
                clearTimerAndDestroySocket();
                if (retriesRemaining >= 0)
                    resolve();
            });
            timer = setTimeout(function () { retry(); }, retryInterval);
            socket.on('error', function (err) {
                clearTimerAndDestroySocket();
                setTimeout(retry, retryInterval);
            });
        }
        tryToConnect();
    });
}
/**
 * An interceptor that does nothing.
 */
function nopInterceptor(m) { }
exports.nopInterceptor = nopInterceptor;
/**
 * Abstract class that represents HTTP headers.
 */
class AbstractHTTPHeaders {
    // The raw headers, as a sequence of key/value pairs.
    // Since header fields may be repeated, this array may contain multiple entries for the same key.
    get headers() {
        return this._headers;
    }
    constructor(headers) {
        this._headers = headers;
    }
    _indexOfHeader(name) {
        const headers = this.headers;
        const len = headers.length;
        for (let i = 0; i < len; i++) {
            if (headers[i][0].toLowerCase() === name) {
                return i;
            }
        }
        return -1;
    }
    /**
     * Get the value of the given header field.
     * If there are multiple fields with that name, this only returns the first field's value!
     * @param name Name of the header field
     */
    getHeader(name) {
        const index = this._indexOfHeader(name.toLowerCase());
        if (index !== -1) {
            return this.headers[index][1];
        }
        return '';
    }
    /**
     * Set the value of the given header field. Assumes that there is only one field with the given name.
     * If the field does not exist, it adds a new field with the name and value.
     * @param name Name of the field.
     * @param value New value.
     */
    setHeader(name, value) {
        const index = this._indexOfHeader(name.toLowerCase());
        if (index !== -1) {
            this.headers[index][1] = value;
        }
        else {
            this.headers.push([name, value]);
        }
    }
    /**
     * Removes the header field with the given name. Assumes that there is only one field with the given name.
     * Does nothing if field does not exist.
     * @param name Name of the field.
     */
    removeHeader(name) {
        const index = this._indexOfHeader(name.toLowerCase());
        if (index !== -1) {
            this.headers.splice(index, 1);
        }
    }
    /**
     * Removes all header fields.
     */
    clearHeaders() {
        this._headers = [];
    }
}
exports.AbstractHTTPHeaders = AbstractHTTPHeaders;
/**
 * Represents a MITM-ed HTTP response from a server.
 */
class InterceptedHTTPResponse extends AbstractHTTPHeaders {
    constructor(metadata) {
        super(metadata.headers);
        this.statusCode = metadata.status_code;
        // We don't support chunked transfers. The proxy already de-chunks it for us.
        this.removeHeader('transfer-encoding');
        // MITMProxy decodes the data for us.
        this.removeHeader('content-encoding');
        // CSP is bad!
        this.removeHeader('content-security-policy');
        this.removeHeader('x-webkit-csp');
        this.removeHeader('x-content-security-policy');
    }
    toJSON() {
        return {
            status_code: this.statusCode,
            headers: this.headers
        };
    }
}
exports.InterceptedHTTPResponse = InterceptedHTTPResponse;
/**
 * Represents an intercepted HTTP request from a client.
 */
class InterceptedHTTPRequest extends AbstractHTTPHeaders {
    constructor(metadata) {
        super(metadata.headers);
        this.method = metadata.method.toLowerCase();
        this.rawUrl = metadata.url;
        this.url = url_1.parse(this.rawUrl);
    }
}
exports.InterceptedHTTPRequest = InterceptedHTTPRequest;
/**
 * Represents an intercepted HTTP request/response pair.
 */
class InterceptedHTTPMessage {
    /**
     * Unpack from a Buffer received from MITMProxy.
     * @param b
     */
    static FromBuffer(b) {
        const metadataSize = b.readInt32LE(0);
        const requestSize = b.readInt32LE(4);
        const responseSize = b.readInt32LE(8);
        const metadata = JSON.parse(b.toString("utf8", 12, 12 + metadataSize));
        return new InterceptedHTTPMessage(new InterceptedHTTPRequest(metadata.request), new InterceptedHTTPResponse(metadata.response), b.slice(12 + metadataSize, 12 + metadataSize + requestSize), b.slice(12 + metadataSize + requestSize, 12 + metadataSize + requestSize + responseSize));
    }
    // The body of the HTTP response. Read-only; change the response body via setResponseBody.
    get responseBody() {
        return this._responseBody;
    }
    constructor(request, response, requestBody, responseBody) {
        this.request = request;
        this.response = response;
        this.requestBody = requestBody;
        this._responseBody = responseBody;
    }
    /**
     * Changes the body of the HTTP response. Appropriately updates content-length.
     * @param b The new body contents.
     */
    setResponseBody(b) {
        this._responseBody = b;
        // Update content-length.
        this.response.setHeader('content-length', `${b.length}`);
        // TODO: Content-encoding?
    }
    /**
     * Pack into a buffer for transmission to MITMProxy.
     */
    toBuffer() {
        const metadata = Buffer.from(JSON.stringify(this.response), 'utf8');
        const metadataLength = metadata.length;
        const responseLength = this._responseBody.length;
        const rv = Buffer.alloc(8 + metadataLength + responseLength);
        rv.writeInt32LE(metadataLength, 0);
        rv.writeInt32LE(responseLength, 4);
        metadata.copy(rv, 8);
        this._responseBody.copy(rv, 8 + metadataLength);
        return rv;
    }
}
exports.InterceptedHTTPMessage = InterceptedHTTPMessage;
class CachedItem {
    constructor(rawUrl, mimeType, data) {
        this.rawUrl = rawUrl;
        this.mimeType = mimeType;
        this.data = data;
    }
    get shortMimeType() {
        let mime = this.mimeType.toLowerCase();
        if (mime.indexOf(";") !== -1) {
            mime = mime.slice(0, mime.indexOf(";"));
        }
        return mime;
    }
    get isHtml() {
        return this.shortMimeType === "text/html";
    }
    get isJavaScript() {
        switch (this.shortMimeType) {
            case 'text/javascript':
            case 'application/javascript':
            case 'text/x-javascript':
            case 'application/x-javascript':
                return true;
            default:
                return false;
        }
    }
}
exports.CachedItem = CachedItem;
/**
 * Class that launches MITM proxy and talks to it via WebSockets.
 */
class MITMProxy {
    constructor(cb) {
        this._cacheEnabled = false;
        this._mitmProcess = null;
        this._mitmError = null;
        this._wss = null;
        this._cache = new Map();
        this.cb = cb;
    }
    static Create(cb = nopInterceptor) {
        return __awaiter(this, void 0, void 0, function* () {
            // Construct WebSocket server, and wait for it to begin listening.
            const wss = new ws_1.Server({ port: 8765 });
            const proxyConnected = new Promise((resolve, reject) => {
                wss.once('connection', () => {
                    resolve();
                });
            });
            const mp = new MITMProxy(cb);
            // Set up WSS callbacks before MITMProxy connects.
            mp._initializeWSS(wss);
            yield new Promise((resolve, reject) => {
                wss.once('listening', () => {
                    wss.removeListener('error', reject);
                    resolve();
                });
                wss.once('error', reject);
            });
            try {
                yield waitForPort(8080, 1);
                console.log(`MITMProxy already running.`);
            }
            catch (e) {
                console.log(`MITMProxy not running; starting up mitmproxy.`);
                // Start up MITM process.
                const mitmProcess = child_process_1.spawn("mitmdump", ["--anticache", "-s", path_1.resolve(__dirname, "../scripts/proxy.py")], {
                    stdio: 'inherit'
                });
                if (MITMProxy._activeProcesses.push(mitmProcess) === 1) {
                    process.on('SIGINT', MITMProxy._cleanup);
                    process.on('exit', MITMProxy._cleanup);
                }
                mp._initializeMITMProxy(mitmProcess);
                // Wait for port 8080 to come online.
                yield waitForPort(8080);
            }
            yield proxyConnected;
            return mp;
        });
    }
    static _cleanup() {
        if (MITMProxy._cleanupCalled) {
            return;
        }
        MITMProxy._cleanupCalled = true;
        MITMProxy._activeProcesses.forEach((p) => {
            p.kill('SIGKILL');
        });
    }
    // Toggle whether or not MITMProxy caches unadulterated server responses.
    // Not used for performance, but enables Node.js code to fetch previous server responses from the proxy.
    get cacheEnabled() {
        return this._cacheEnabled;
    }
    set cacheEnabled(v) {
        if (!v) {
            this._cache.clear();
        }
        this._cacheEnabled = v;
    }
    _initializeWSS(wss) {
        this._wss = wss;
        this._wss.on('connection', (ws) => {
            ws.on('message', (message) => {
                const original = InterceptedHTTPMessage.FromBuffer(message);
                this.cb(original);
                // Remove transfer-encoding. We don't support chunked.
                if (this._cacheEnabled) {
                    this._cache.set(original.request.rawUrl, new CachedItem(original.request.rawUrl, original.response.getHeader('content-type'), original.responseBody));
                }
                ws.send(original.toBuffer());
            });
        });
    }
    _initializeMITMProxy(mitmProxy) {
        this._mitmProcess = mitmProxy;
        this._mitmProcess.on('exit', (code, signal) => {
            const index = MITMProxy._activeProcesses.indexOf(this._mitmProcess);
            if (index !== -1) {
                MITMProxy._activeProcesses.splice(index, 1);
            }
            if (code !== null) {
                if (code !== 0) {
                    this._mitmError = new Error(`Process exited with code ${code}.`);
                }
            }
            else {
                this._mitmError = new Error(`Process exited due to signal ${signal}.`);
            }
        });
        this._mitmProcess.on('error', (err) => {
            this._mitmError = err;
        });
    }
    /**
     * Retrieves the given URL from the cache.
     * @param url
     */
    getFromCache(url) {
        return this._cache.get(url);
    }
    forEachCacheItem(cb) {
        this._cache.forEach(cb);
    }
    /**
     * Requests the given URL from the proxy.
     */
    proxyGet(urlString) {
        return __awaiter(this, void 0, void 0, function* () {
            const url = url_1.parse(urlString);
            const get = url.protocol === "http:" ? http_1.get : https_1.get;
            return new Promise((resolve, reject) => {
                const req = get({
                    url: urlString,
                    headers: {
                        host: url.host
                    },
                    host: 'localhost',
                    port: 8080,
                    path: urlString
                }, (res) => {
                    const data = new Array();
                    res.on('data', (chunk) => {
                        data.push(chunk);
                    });
                    res.on('end', () => {
                        const d = Buffer.concat(data);
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            body: d
                        });
                    });
                    res.once('error', reject);
                });
                req.once('error', reject);
            });
        });
    }
    shutdown() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                const closeWSS = () => {
                    this._wss.close((err) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve();
                        }
                    });
                };
                if (this._mitmProcess && this._mitmProcess.connected) {
                    this._mitmProcess.once('exit', (code, signal) => {
                        closeWSS();
                    });
                    this._mitmProcess.kill();
                }
                else {
                    closeWSS();
                }
            });
        });
    }
}
MITMProxy._activeProcesses = [];
MITMProxy._cleanupCalled = false;
exports.default = MITMProxy;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQUFBLDJCQUE2QztBQUM3QyxpREFBa0Q7QUFDbEQsK0JBQTZCO0FBQzdCLDZCQUEyQztBQUMzQywrQkFBb0M7QUFDcEMsaUNBQXNDO0FBQ3RDLDZCQUE2QztBQUU3Qzs7Ozs7R0FLRztBQUNILHFCQUFxQixJQUFZLEVBQUUsVUFBa0IsRUFBRSxFQUFFLFdBQW1CLEdBQUc7SUFDN0UsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQzNDLElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDO1FBQy9CLElBQUksYUFBYSxHQUFHLFFBQVEsQ0FBQztRQUM3QixJQUFJLEtBQUssR0FBaUIsSUFBSSxDQUFDO1FBQy9CLElBQUksTUFBTSxHQUFXLElBQUksQ0FBQztRQUUxQjtZQUNFLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUNwQixLQUFLLEdBQUcsSUFBSSxDQUFDO1lBQ2IsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDO2dCQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUM3QixNQUFNLEdBQUcsSUFBSSxDQUFDO1FBQ2hCLENBQUM7UUFFRDtZQUNFLFlBQVksRUFBRSxDQUFDO1FBQ2pCLENBQUM7UUFFRDtZQUNFLDBCQUEwQixFQUFFLENBQUM7WUFFN0IsRUFBRSxDQUFDLENBQUMsRUFBRSxnQkFBZ0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMzQixNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDO1lBQ3RDLENBQUM7WUFFRCxNQUFNLEdBQUcsc0JBQWdCLENBQUMsSUFBSSxFQUFFLFdBQVcsRUFBRTtnQkFDM0MsMEJBQTBCLEVBQUUsQ0FBQztnQkFDN0IsRUFBRSxDQUFDLENBQUMsZ0JBQWdCLElB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UUFBUTs7WUFDbkIsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO2dCQUMzQyxNQUFNLFFBQVEsR0FBRyxHQUFHLEVBQUU7b0JBQ3BCLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUU7d0JBQ3RCLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7NEJBQ1IsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO3dCQUNkLENBQUM7d0JBQUMsSUFBSSxDQUFDLENBQUM7NEJBQ04sT0FBTyxFQUFFLENBQUM7d0JBQ1osQ0FBQztvQkFDSCxDQUFDLENBQUMsQ0FBQztnQkFDTCxDQUFDLENBQUM7Z0JBRUYsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFlBQVksSUFBSSxJQUFJLENBQUMsWUFBWSxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUM7b0JBQ3JELElBQUksQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRSxDQUFDLElBQUksRUFBRSxNQUFNLEVBQUUsRUFBRTt3QkFDOUMsUUFBUSxFQUFFLENBQUM7b0JBQ2IsQ0FBQyxDQUFDLENBQUM7b0JBQ0gsSUFBSSxDQUFDLFlBQVksQ0FBQyxJQUFJLEVBQUUsQ0FBQztnQkFDM0IsQ0FBQztnQkFBQyxJQUFJLENBQUMsQ0FBQztvQkFDTixRQUFRLEVBQUUsQ0FBQztnQkFDYixDQUFDO1lBQ0gsQ0FBQyxDQUFDLENBQUM7UUFDTCxDQUFDO0tBQUE7O0FBbkxjLDBCQUFnQixHQUFtQixFQUFFLENBQUM7QUEyQ3RDLHdCQUFjLEdBQUcsS0FBSyxDQUFDO0FBNUN4Qyw0QkFxTEMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1NlcnZlciBhcyBXZWJTb2NrZXRTZXJ2ZXJ9IGZyb20gJ3dzJztcbmltcG9ydCB7c3Bhd24sIENoaWxkUHJvY2Vzc30gZnJvbSAnY2hpbGRfcHJvY2Vzcyc7XG5pbXBvcnQge3Jlc29sdmV9IGZyb20gJ3BhdGgnO1xuaW1wb3J0IHtwYXJzZSBhcyBwYXJzZVVSTCwgVXJsfSBmcm9tICd1cmwnO1xuaW1wb3J0IHtnZXQgYXMgaHR0cEdldH0gZnJvbSAnaHR0cCc7XG5pbXBvcnQge2dldCBhcyBodHRwc0dldH0gZnJvbSAnaHR0cHMnO1xuaW1wb3J0IHtjcmVhdGVDb25uZWN0aW9uLCBTb2NrZXR9IGZyb20gJ25ldCc7XG5cbi8qKlxuICogV2FpdCBmb3IgdGhlIHNwZWNpZmllZCBwb3J0IHRvIG9wZW4uXG4gKiBAcGFyYW0gcG9ydCBUaGUgcG9ydCB0byB3YXRjaCBmb3IuXG4gKiBAcGFyYW0gcmV0cmllcyBUaGUgbnVtYmVyIG9mIHRpbWVzIHRvIHJldHJ5IGJlZm9yZSBnaXZpbmcgdXAuIERlZmF1bHRzIHRvIDEwLlxuICogQHBhcmFtIGludGVydmFsIFRoZSBpbnRlcnZhbCBiZXR3ZWVuIHJldHJpZXMsIGluIG1pbGxpc2Vjb25kcy4gRGVmYXVsdHMgdG8gNTAwLlxuICovXG5mdW5jdGlvbiB3YWl0Rm9yUG9ydChwb3J0OiBudW1iZXIsIHJldHJpZXM6IG51bWJlciA9IDEwLCBpbnRlcnZhbDogbnVtYmVyID0gNTAwKTogUHJvbWlzZTx2b2lkPiB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgbGV0IHJldHJpZXNSZW1haW5pbmcgPSByZXRyaWVzO1xuICAgIGxldCByZXRyeUludGVydmFsID0gaW50ZXJ2YWw7XG4gICAgbGV0IHRpbWVyOiBOb2RlSlMuVGltZXIgPSBudWxsO1xuICAgIGxldCBzb2NrZXQ6IFNvY2tldCA9IG51bGw7XG5cbiAgICBmdW5jdGlvbiBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aW1lcik7XG4gICAgICB0aW1lciA9IG51bGw7XG4gICAgICBpZiAoc29ja2V0KSBzb2NrZXQuZGVzdHJveSgpO1xuICAgICAgc29ja2V0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZXRyeSgpIHtcbiAgICAgIHRyeVRvQ29ubmVjdCgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyeVRvQ29ubmVjdCgpIHtcbiAgICAgIGNsZWFyVGltZXJBbmREZXN0cm95U29ja2V0KCk7XG5cbiAgICAgIGlmICgtLXJldHJpZXNSZW1haW5pbmcgPCAwKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ291dCBvZiByZXRyaWVzJykpO1xuICAgICAgfVxuXG4gICAgICBzb2NrZXQgPSBjcmVhdGVDb25uZWN0aW9uKHBvcnQsIFwibG9jYWxob3N0XCIsIGZ1bmN0aW9uKCkge1xuICAgICAgICBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpO1xuICAgICAgICBpZiAocmV0cmllc1JlbWFpbmluZyA+PSAwKSByZXNvbHZlKCk7XG4gICAgICB9KTtcblxuICAgICAgdGltZXIgPSBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgeyByZXRyeSgpOyB9LCByZXRyeUludGVydmFsKTtcblxuICAgICAgc29ja2V0Lm9uKCdlcnJvcicsIGZ1bmN0aW9uKGVycikge1xuICAgICAgICBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpO1xuICAgICAgICBzZXRUaW1lb3V0KHJldHJ5LCByZXRyeUludGVydmFsKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHRyeVRvQ29ubmVjdCgpO1xuICB9KTtcbn1cblxuLyoqXG4gKiBGdW5jdGlvbiB0aGF0IGludGVyY2VwdHMgYW5kIHJld3JpdGVzIEhUVFAgcmVzcG9uc2VzLlxuICovXG5leHBvcnQgdHlwZSBJbnRlcmNlcHRvciA9IChtOiBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlKSA9PiB2b2lkO1xuXG4vKipcbiAqIEFuIGludGVyY2VwdG9yIHRoYXQgZG9lcyBub3RoaW5nLlxuICovXG5leHBvcnQgZnVuY3Rpb24gbm9wSW50ZXJjZXB0b3IobTogSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZSk6IHZvaWQge31cblxuLyoqXG4gKiBUaGUgY29yZSBIVFRQIHJlc3BvbnNlLlxuICovXG5leHBvcnQgaW50ZXJmYWNlIEhUVFBSZXNwb25zZSB7XG4gIHN0YXR1c0NvZGU6IG51bWJlcixcbiAgaGVhZGVyczoge1tuYW1lOiBzdHJpbmddOiBzdHJpbmd9O1xuICBib2R5OiBCdWZmZXI7XG59XG5cbi8qKlxuICogTWV0YWRhdGEgYXNzb2NpYXRlZCB3aXRoIGEgcmVxdWVzdC9yZXNwb25zZSBwYWlyLlxuICovXG5pbnRlcmZhY2UgSFRUUE1lc3NhZ2VNZXRhZGF0YSB7XG4gIHJlcXVlc3Q6IEhUVFBSZXF1ZXN0TWV0YWRhdGE7XG4gIHJlc3BvbnNlOiBIVFRQUmVzcG9uc2VNZXRhZGF0YTtcbn1cblxuLyoqXG4gKiBNZXRhZGF0YSBhc3NvY2lhdGVkIHdpdGggYW4gSFRUUCByZXF1ZXN0LlxuICovXG5leHBvcnQgaW50ZXJmYWNlIEhUVFBSZXF1ZXN0TWV0YWRhdGEge1xuICAvLyBHRVQsIERFTEVURSwgUE9TVCwgIGV0Yy5cbiAgbWV0aG9kOiBzdHJpbmc7XG4gIC8vIFRhcmdldCBVUkwgZm9yIHRoZSByZXF1ZXN0LlxuICB1cmw6IHN0cmluZztcbiAgLy8gVGhlIHNldCBvZiBoZWFkZXJzIGZyb20gdGhlIHJlcXVlc3QsIGFzIGtleS12YWx1ZSBwYWlycy5cbiAgLy8gU2luY2UgaGVhZGVyIGZpZWxkcyBtYXkgYmUgcmVwZWF0ZWQsIHRoaXMgYXJyYXkgbWF5IGNvbnRhaW4gbXVsdGlwbGUgZW50cmllcyBmb3IgdGhlIHNhbWUga2V5LlxuICBoZWFkZXJzOiBbc3RyaW5nLCBzdHJpbmddW107XG59XG5cbi8qKlxuICogTWV0YWRhdGEgYXNzb2NpYXRlZCB3aXRoIGFuIEhUVFAgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSFRUUFJlc3BvbnNlTWV0YWRhdGEge1xuICAvLyBUaGUgbnVtZXJpY2FsIHN0YXR1cyBjb2RlLlxuICBzdGF0dXNfY29kZTogbnVtYmVyO1xuICAvLyBUaGUgc2V0IG9mIGhlYWRlcnMgZnJvbSB0aGUgcmVzcG9uc2UsIGFzIGtleS12YWx1ZSBwYWlycy5cbiAgLy8gU2luY2UgaGVhZGVyIGZpZWxkcyBtYXkgYmUgcmVwZWF0ZWQsIHRoaXMgYXJyYXkgbWF5IGNvbnRhaW4gbXVsdGlwbGUgZW50cmllcyBmb3IgdGhlIHNhbWUga2V5LlxuICBoZWFkZXJzOiBbc3RyaW5nLCBzdHJpbmddW107XG59XG5cbi8qKlxuICogQWJzdHJhY3QgY2xhc3MgdGhhdCByZXByZXNlbnRzIEhUVFAgaGVhZGVycy5cbiAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEFic3RyYWN0SFRUUEhlYWRlcnMge1xuICBwcml2YXRlIF9oZWFkZXJzOiBbc3RyaW5nLCBzdHJpbmddW107XG4gIC8vIFRoZSByYXcgaGVhZGVycywgYXMgYSBzZXF1ZW5jZSBvZiBrZXkvdmFsdWUgcGFpcnMuXG4gIC8vIFNpbmNlIGhlYWRlciBmaWVsZHMgbWF5IGJlIHJlcGVhdGVkLCB0aGlzIGFycmF5IG1heSBjb250YWluIG11bHRpcGxlIGVudHJpZXMgZm9yIHRoZSBzYW1lIGtleS5cbiAgcHVibGljIGdldCBoZWFkZXJzKCk6IFtzdHJpbmcsIHN0cmluZ11bXSB7XG4gICAgcmV0dXJuIHRoaXMuX2hlYWRlcnM7XG4gIH1cbiAgY29uc3RydWN0b3IoaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdKSB7XG4gICAgdGhpcy5faGVhZGVycyA9IGhlYWRlcnM7XG4gIH1cblxuICBwcml2YXRlIF9pbmRleE9mSGVhZGVyKG5hbWU6IHN0cmluZyk6IG51bWJlciB7XG4gICAgY29uc3QgaGVhZGVycyA9IHRoaXMuaGVhZGVycztcbiAgICBjb25zdCBsZW4gPSBoZWFkZXJzLmxlbmd0aDtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgICBpZiAoaGVhZGVyc1tpXVswXS50b0xvd2VyQ2FzZSgpID09PSBuYW1lKSB7XG4gICAgICAgIHJldHVybiBpO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gLTE7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSB2YWx1ZSBvZiB0aGUgZ2l2ZW4gaGVhZGVyIGZpZWxkLlxuICAgKiBJZiB0aGVyZSBhcmUgbXVsdGlwbGUgZmllbGRzIHdpdGggdGhhdCBuYW1lLCB0aGlzIG9ubHkgcmV0dXJucyB0aGUgZmlyc3QgZmllbGQncyB2YWx1ZSFcbiAgICogQHBhcmFtIG5hbWUgTmFtZSBvZiB0aGUgaGVhZGVyIGZpZWxkXG4gICAqL1xuICBwdWJsaWMgZ2V0SGVhZGVyKG5hbWU6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgY29uc3QgaW5kZXggPSB0aGlzLl9pbmRleE9mSGVhZGVyKG5hbWUudG9Mb3dlckNhc2UoKSk7XG4gICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgcmV0dXJuIHRoaXMuaGVhZGVyc1tpbmRleF1bMV07XG4gICAgfVxuICAgIHJldHVybiAnJztcbiAgfVxuXG4gIC8qKlxuICAgKiBTZXQgdGhlIHZhbHVlIG9mIHRoZSBnaXZlbiBoZWFkZXIgZmllbGQuIEFzc3VtZXMgdGhhdCB0aGVyZSBpcyBvbmx5IG9uZSBmaWVsZCB3aXRoIHRoZSBnaXZlbiBuYW1lLlxuICAgKiBJZiB0aGUgZmllbGQgZG9lcyBub3QgZXhpc3QsIGl0IGFkZHMgYSBuZXcgZmllbGQgd2l0aCB0aGUgbmFtZSBhbmQgdmFsdWUuXG4gICAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGZpZWxkLlxuICAgKiBAcGFyYW0gdmFsdWUgTmV3IHZhbHVlLlxuICAgKi9cbiAgcHVibGljIHNldEhlYWRlcihuYW1lOiBzdHJpbmcsIHZhbHVlOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBjb25zdCBpbmRleCA9IHRoaXMuX2luZGV4T2ZIZWFkZXIobmFtZS50b0xvd2VyQ2FzZSgpKTtcbiAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICB0aGlzLmhlYWRlcnNbaW5kZXhdWzFdID0gdmFsdWU7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuaGVhZGVycy5wdXNoKFtuYW1lLCB2YWx1ZV0pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmVzIHRoZSBoZWFkZXIgZmllbGQgd2l0aCB0aGUgZ2l2ZW4gbmFtZS4gQXNzdW1lcyB0aGF0IHRoZXJlIGlzIG9ubHkgb25lIGZpZWxkIHdpdGggdGhlIGdpdmVuIG5hbWUuXG4gICAqIERvZXMgbm90aGluZyBpZiBmaWVsZCBkb2VzIG5vdCBleGlzdC5cbiAgICogQHBhcmFtIG5hbWUgTmFtZSBvZiB0aGUgZmllbGQuXG4gICAqL1xuICBwdWJsaWMgcmVtb3ZlSGVhZGVyKG5hbWU6IHN0cmluZyk6IHZvaWQge1xuICAgIGNvbnN0IGluZGV4ID0gdGhpcy5faW5kZXhPZkhlYWRlcihuYW1lLnRvTG93ZXJDYXNlKCkpO1xuICAgIGlmIChpbmRleCAhPT0gLTEpIHtcbiAgICAgIHRoaXMuaGVhZGVycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmVzIGFsbCBoZWFkZXIgZmllbGRzLlxuICAgKi9cbiAgcHVibGljIGNsZWFySGVhZGVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9oZWFkZXJzID0gW107XG4gIH1cbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIGEgTUlUTS1lZCBIVFRQIHJlc3BvbnNlIGZyb20gYSBzZXJ2ZXIuXG4gKi9cbmV4cG9ydCBjbGFzcyBJbnRlcmNlcHRlZEhUVFBSZXNwb25zZSBleHRlbmRzIEFic3RyYWN0SFRUUEhlYWRlcnMge1xuICAvLyBUaGUgc3RhdHVzIGNvZGUgb2YgdGhlIEhUVFAgcmVzcG9uc2UuXG4gIHB1YmxpYyBzdGF0dXNDb2RlOiBudW1iZXI7XG5cbiAgY29uc3RydWN0b3IobWV0YWRhdGE6IEhUVFBSZXNwb25zZU1ldGFkYXRhKSB7XG4gICAgc3VwZXIobWV0YWRhdGEuaGVhZGVycyk7XG4gICAgdGhpcy5zdGF0dXNDb2RlID0gbWV0YWRhdGEuc3RhdHVzX2NvZGU7XG4gICAgLy8gV2UgZG9uJ3Qgc3VwcG9ydCBjaHVua2VkIHRyYW5zZmVycy4gVGhlIHByb3h5IGFscmVhZHkgZGUtY2h1bmtzIGl0IGZvciB1cy5cbiAgICB0aGlzLnJlbW92ZUhlYWRlcigndHJhbnNmZXItZW5jb2RpbmcnKTtcbiAgICAvLyBNSVRNUHJveHkgZGVjb2RlcyB0aGUgZGF0YSBmb3IgdXMuXG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ2NvbnRlbnQtZW5jb2RpbmcnKTtcbiAgICAvLyBDU1AgaXMgYmFkIVxuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCdjb250ZW50LXNlY3VyaXR5LXBvbGljeScpO1xuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCd4LXdlYmtpdC1jc3AnKTtcbiAgICB0aGlzLnJlbW92ZUhlYWRlcigneC1jb250ZW50LXNlY3VyaXR5LXBvbGljeScpO1xuICB9XG5cbiAgcHVibGljIHRvSlNPTigpOiBIVFRQUmVzcG9uc2VNZXRhZGF0YSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHN0YXR1c19jb2RlOiB0aGlzLnN0YXR1c0NvZGUsXG4gICAgICBoZWFkZXJzOiB0aGlzLmhlYWRlcnNcbiAgICB9O1xuICB9XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyBhbiBpbnRlcmNlcHRlZCBIVFRQIHJlcXVlc3QgZnJvbSBhIGNsaWVudC5cbiAqL1xuZXhwb3J0IGNsYXNzIEludGVyY2VwdGVkSFRUUFJlcXVlc3QgZXh0ZW5kcyBBYnN0cmFjdEhUVFBIZWFkZXJzIHtcbiAgLy8gSFRUUCBtZXRob2QgKEdFVC9ERUxFVEUvZXRjKVxuICBwdWJsaWMgbWV0aG9kOiBzdHJpbmc7XG4gIC8vIFRoZSBVUkwgYXMgYSBzdHJpbmcuXG4gIHB1YmxpYyByYXdVcmw6IHN0cmluZztcbiAgLy8gVGhlIFVSTCBhcyBhIFVSTCBvYmplY3QuXG4gIHB1YmxpYyB1cmw6IFVybDtcblxuICBjb25zdHJ1Y3RvcihtZXRhZGF0YTogSFRUUFJlcXVlc3RNZXRhZGF0YSkge1xuICAgIHN1cGVyKG1ldGFkYXRhLmhlYWRlcnMpO1xuICAgIHRoaXMubWV0aG9kID0gbWV0YWRhdGEubWV0aG9kLnRvTG93ZXJDYXNlKCk7XG4gICAgdGhpcy5yYXdVcmwgPSBtZXRhZGF0YS51cmw7XG4gICAgdGhpcy51cmwgPSBwYXJzZVVSTCh0aGlzLnJhd1VybCk7XG4gIH1cbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIGFuIGludGVyY2VwdGVkIEhUVFAgcmVxdWVzdC9yZXNwb25zZSBwYWlyLlxuICovXG5leHBvcnQgY2xhc3MgSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZSB7XG4gIC8qKlxuICAgKiBVbnBhY2sgZnJvbSBhIEJ1ZmZlciByZWNlaXZlZCBmcm9tIE1JVE1Qcm94eS5cbiAgICogQHBhcmFtIGJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgRnJvbUJ1ZmZlcihiOiBCdWZmZXIpOiBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlIHtcbiAgICBjb25zdCBtZXRhZGF0YVNpemUgPSBiLnJlYWRJbnQzMkxFKDApO1xuICAgIGNvbnN0IHJlcXVlc3RTaXplID0gYi5yZWFkSW50MzJMRSg0KTtcbiAgICBjb25zdCByZXNwb25zZVNpemUgPSBiLnJlYWRJbnQzMkxFKDgpO1xuICAgIGNvbnN0IG1ldGFkYXRhOiBIVFRQTWVzc2FnZU1ldGFkYXRhID0gSlNPTi5wYXJzZShiLnRvU3RyaW5nKFwidXRmOFwiLCAxMiwgMTIgKyBtZXRhZGF0YVNpemUpKTtcbiAgICByZXR1cm4gbmV3IEludGVyY2VwdGVkSFRUUE1lc3NhZ2UoXG4gICAgICBuZXcgSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdChtZXRhZGF0YS5yZXF1ZXN0KSxcbiAgICAgIG5ldyBJbnRlcmNlcHRlZEhUVFBSZXNwb25zZShtZXRhZGF0YS5yZXNwb25zZSksXG4gICAgICBiLnNsaWNlKDEyICsgbWV0YWRhdGFTaXplLCAxMiArIG1ldGFkYXRhU2l6ZSArIHJlcXVlc3RTaXplKSxcbiAgICAgIGIuc2xpY2UoMTIgKyBtZXRhZGF0YVNpemUgKyByZXF1ZXN0U2l6ZSwgMTIgKyBtZXRhZGF0YVNpemUgKyByZXF1ZXN0U2l6ZSArIHJlc3BvbnNlU2l6ZSlcbiAgICApO1xuICB9XG5cbiAgcHVibGljIHJlYWRvbmx5IHJlcXVlc3Q6IEludGVyY2VwdGVkSFRUUFJlcXVlc3Q7XG4gIHB1YmxpYyByZWFkb25seSByZXNwb25zZTogSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2U7XG4gIC8vIFRoZSBib2R5IG9mIHRoZSBIVFRQIHJlcXVlc3QuXG4gIHB1YmxpYyByZWFkb25seSByZXF1ZXN0Qm9keTogQnVmZmVyO1xuICAvLyBUaGUgYm9keSBvZiB0aGUgSFRUUCByZXNwb25zZS4gUmVhZC1vbmx5OyBjaGFuZ2UgdGhlIHJlc3BvbnNlIGJvZHkgdmlhIHNldFJlc3BvbnNlQm9keS5cbiAgcHVibGljIGdldCByZXNwb25zZUJvZHkoKTogQnVmZmVyIHtcbiAgICByZXR1cm4gdGhpcy5fcmVzcG9uc2VCb2R5O1xuICB9XG4gIHByaXZhdGUgX3Jlc3BvbnNlQm9keTogQnVmZmVyO1xuICBwcml2YXRlIGNvbnN0cnVjdG9yKHJlcXVlc3Q6IEludGVyY2VwdGVkSFRUUFJlcXVlc3QsIHJlc3BvbnNlOiBJbnRlcmNlcHRlZEhUVFBSZXNwb25zZSwgcmVxdWVzdEJvZHk6IEJ1ZmZlciwgcmVzcG9uc2VCb2R5OiBCdWZmZXIpIHtcbiAgICB0aGlzLnJlcXVlc3QgPSByZXF1ZXN0O1xuICAgIHRoaXMucmVzcG9uc2UgPSByZXNwb25zZTtcbiAgICB0aGlzLnJlcXVlc3RCb2R5ID0gcmVxdWVzdEJvZHk7XG4gICAgdGhpcy5fcmVzcG9uc2VCb2R5ID0gcmVzcG9uc2VCb2R5O1xuICB9XG5cbiAgLyoqXG4gICAqIENoYW5nZXMgdGhlIGJvZHkgb2YgdGhlIEhUVFAgcmVzcG9uc2UuIEFwcHJvcHJpYXRlbHkgdXBkYXRlcyBjb250ZW50LWxlbmd0aC5cbiAgICogQHBhcmFtIGIgVGhlIG5ldyBib2R5IGNvbnRlbnRzLlxuICAgKi9cbiAgcHVibGljIHNldFJlc3BvbnNlQm9keShiOiBCdWZmZXIpIHtcbiAgICB0aGlzLl9yZXNwb25zZUJvZHkgPSBiO1xuICAgIC8vIFVwZGF0ZSBjb250ZW50LWxlbmd0aC5cbiAgICB0aGlzLnJlc3BvbnNlLnNldEhlYWRlcignY29udGVudC1sZW5ndGgnLCBgJHtiLmxlbmd0aH1gKTtcbiAgICAvLyBUT0RPOiBDb250ZW50LWVuY29kaW5nP1xuICB9XG5cbiAgLyoqXG4gICAqIFBhY2sgaW50byBhIGJ1ZmZlciBmb3IgdHJhbnNtaXNzaW9uIHRvIE1JVE1Qcm94eS5cbiAgICovXG4gIHB1YmxpYyB0b0J1ZmZlcigpOiBCdWZmZXIge1xuICAgIGNvbnN0IG1ldGFkYXRhID0gQnVmZmVyLmZyb20oSlNPTi5zdHJpbmdpZnkodGhpcy5yZXNwb25zZSksICd1dGY4Jyk7XG4gICAgY29uc3QgbWV0YWRhdGFMZW5ndGggPSBtZXRhZGF0YS5sZW5ndGg7XG4gICAgY29uc3QgcmVzcG9uc2VMZW5ndGggPSB0aGlzLl9yZXNwb25zZUJvZHkubGVuZ3RoXG4gICAgY29uc3QgcnYgPSBCdWZmZXIuYWxsb2MoOCArIG1ldGFkYXRhTGVuZ3RoICsgcmVzcG9uc2VMZW5ndGgpO1xuICAgIHJ2LndyaXRlSW50MzJMRShtZXRhZGF0YUxlbmd0aCwgMCk7XG4gICAgcnYud3JpdGVJbnQzMkxFKHJlc3BvbnNlTGVuZ3RoLCA0KTtcbiAgICBtZXRhZGF0YS5jb3B5KHJ2LCA4KTtcbiAgICB0aGlzLl9yZXNwb25zZUJvZHkuY29weShydiwgOCArIG1ldGFkYXRhTGVuZ3RoKTtcbiAgICByZXR1cm4gcnY7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIENhY2hlZEl0ZW0ge1xuICBjb25zdHJ1Y3RvcihcbiAgICBwdWJsaWMgcmVhZG9ubHkgcmF3VXJsOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IG1pbWVUeXBlOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IGRhdGE6IEJ1ZmZlcikge31cblxuICBwdWJsaWMgZ2V0IHNob3J0TWltZVR5cGUoKTogc3RyaW5nIHtcbiAgICBsZXQgbWltZSA9IHRoaXMubWltZVR5cGUudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAobWltZS5pbmRleE9mKFwiO1wiKSAhPT0gLTEpIHtcbiAgICAgIG1pbWUgPSBtaW1lLnNsaWNlKDAsIG1pbWUuaW5kZXhPZihcIjtcIikpO1xuICAgIH1cbiAgICByZXR1cm4gbWltZTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgaXNIdG1sKCk6IGJvb2xlYW4ge1xuICAgIHJldHVybiB0aGlzLnNob3J0TWltZVR5cGUgPT09IFwidGV4dC9odG1sXCI7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGlzSmF2YVNjcmlwdCgpOiBib29sZWFuIHtcbiAgICBzd2l0Y2godGhpcy5zaG9ydE1pbWVUeXBlKSB7XG4gICAgICBjYXNlICd0ZXh0L2phdmFzY3JpcHQnOlxuICAgICAgY2FzZSAnYXBwbGljYXRpb24vamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICd0ZXh0L3gtamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICdhcHBsaWNhdGlvbi94LWphdmFzY3JpcHQnOlxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cbn1cblxuLyoqXG4gKiBDbGFzcyB0aGF0IGxhdW5jaGVzIE1JVE0gcHJveHkgYW5kIHRhbGtzIHRvIGl0IHZpYSBXZWJTb2NrZXRzLlxuICovXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNSVRNUHJveHkge1xuICBwcml2YXRlIHN0YXRpYyBfYWN0aXZlUHJvY2Vzc2VzOiBDaGlsZFByb2Nlc3NbXSA9IFtdO1xuXG4gIHB1YmxpYyBzdGF0aWMgYXN5bmMgQ3JlYXRlKGNiOiBJbnRlcmNlcHRvciA9IG5vcEludGVyY2VwdG9yKTogUHJvbWlzZTxNSVRNUHJveHk+IHtcbiAgICAvLyBDb25zdHJ1Y3QgV2ViU29ja2V0IHNlcnZlciwgYW5kIHdhaXQgZm9yIGl0IHRvIGJlZ2luIGxpc3RlbmluZy5cbiAgICBjb25zdCB3c3MgPSBuZXcgV2ViU29ja2V0U2VydmVyKHsgcG9ydDogODc2NSB9KTtcbiAgICBjb25zdCBwcm94eUNvbm5lY3RlZCA9IG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHdzcy5vbmNlKCdjb25uZWN0aW9uJywgKCkgPT4ge1xuICAgICAgICByZXNvbHZlKCk7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgICBjb25zdCBtcCA9IG5ldyBNSVRNUHJveHkoY2IpO1xuICAgIC8vIFNldCB1cCBXU1MgY2FsbGJhY2tzIGJlZm9yZSBNSVRNUHJveHkgY29ubmVjdHMuXG4gICAgbXAuX2luaXRpYWxpemVXU1Mod3NzKTtcbiAgICBhd2FpdCBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB3c3Mub25jZSgnbGlzdGVuaW5nJywgKCkgPT4ge1xuICAgICAgICB3c3MucmVtb3ZlTGlzdGVuZXIoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgfSk7XG4gICAgICB3c3Mub25jZSgnZXJyb3InLCByZWplY3QpO1xuICAgIH0pO1xuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHdhaXRGb3JQb3J0KDgwODAsIDEpO1xuICAgICAgY29uc29sZS5sb2coYE1JVE1Qcm94eSBhbHJlYWR5IHJ1bm5pbmcuYCk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5sb2coYE1JVE1Qcm94eSBub3QgcnVubmluZzsgc3RhcnRpbmcgdXAgbWl0bXByb3h5LmApO1xuICAgICAgLy8gU3RhcnQgdXAgTUlUTSBwcm9jZXNzLlxuICAgICAgY29uc3QgbWl0bVByb2Nlc3MgPSBzcGF3bihcIm1pdG1kdW1wXCIsIFtcIi0tYW50aWNhY2hlXCIsIFwiLXNcIiwgcmVzb2x2ZShfX2Rpcm5hbWUsIFwiLi4vc2NyaXB0cy9wcm94eS5weVwiKV0sIHtcbiAgICAgICAgc3RkaW86ICdpbmhlcml0J1xuICAgICAgfSk7XG4gICAgICBpZiAoTUlUTVByb3h5Ll9hY3RpdmVQcm9jZXNzZXMucHVzaChtaXRtUHJvY2VzcykgPT09IDEpIHtcbiAgICAgICAgcHJvY2Vzcy5vbignU0lHSU5UJywgTUlUTVByb3h5Ll9jbGVhbnVwKTtcbiAgICAgICAgcHJvY2Vzcy5vbignZXhpdCcsIE1JVE1Qcm94eS5fY2xlYW51cCk7XG4gICAgICB9XG4gICAgICBtcC5faW5pdGlhbGl6ZU1JVE1Qcm94eShtaXRtUHJvY2Vzcyk7XG4gICAgICAvLyBXYWl0IGZvciBwb3J0IDgwODAgdG8gY29tZSBvbmxpbmUuXG4gICAgICBhd2FpdCB3YWl0Rm9yUG9ydCg4MDgwKTtcbiAgICB9XG4gICAgYXdhaXQgcHJveHlDb25uZWN0ZWQ7XG5cbiAgICByZXR1cm4gbXA7XG4gIH1cblxuICBwcml2YXRlIHN0YXRpYyBfY2xlYW51cENhbGxlZCA9IGZhbHNlO1xuICBwcml2YXRlIHN0YXRpYyBfY2xlYW51cCgpOiB2b2lkIHtcbiAgICBpZiAoTUlUTVByb3h5Ll9jbGVhbnVwQ2FsbGVkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIE1JVE1Qcm94eS5fY2xlYW51cENhbGxlZCA9IHRydWU7XG4gICAgTUlUTVByb3h5Ll9hY3RpdmVQcm9jZXNzZXMuZm9yRWFjaCgocCkgPT4ge1xuICAgICAgcC5raWxsKCdTSUdLSUxMJyk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9jYWNoZUVuYWJsZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbiAgLy8gVG9nZ2xlIHdoZXRoZXIgb3Igbm90IE1JVE1Qcm94eSBjYWNoZXMgdW5hZHVsdGVyYXRlZCBzZXJ2ZXIgcmVzcG9uc2VzLlxuICAvLyBOb3QgdXNlZCBmb3IgcGVyZm9ybWFuY2UsIGJ1dCBlbmFibGVzIE5vZGUuanMgY29kZSB0byBmZXRjaCBwcmV2aW91cyBzZXJ2ZXIgcmVzcG9uc2VzIGZyb20gdGhlIHByb3h5LlxuICBwdWJsaWMgZ2V0IGNhY2hlRW5hYmxlZCgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gdGhpcy5fY2FjaGVFbmFibGVkO1xuICB9XG4gIHB1YmxpYyBzZXQgY2FjaGVFbmFibGVkKHY6IGJvb2xlYW4pIHtcbiAgICBpZiAoIXYpIHtcbiAgICAgIHRoaXMuX2NhY2hlLmNsZWFyKCk7XG4gICAgfVxuICAgIHRoaXMuX2NhY2hlRW5hYmxlZCA9IHY7XG4gIH1cbiAgcHJpdmF0ZSBfbWl0bVByb2Nlc3M6IENoaWxkUHJvY2VzcyA9IG51bGw7XG4gIHByaXZhdGUgX21pdG1FcnJvcjogRXJyb3IgPSBudWxsO1xuICBwcml2YXRlIF93c3M6IFdlYlNvY2tldFNlcnZlciA9IG51bGw7XG4gIHB1YmxpYyBjYjogSW50ZXJjZXB0b3I7XG4gIHByaXZhdGUgX2NhY2hlID0gbmV3IE1hcDxzdHJpbmcsIENhY2hlZEl0ZW0+KCk7XG5cbiAgcHJpdmF0ZSBjb25zdHJ1Y3RvcihjYjogSW50ZXJjZXB0b3IpIHtcbiAgICB0aGlzLmNiID0gY2I7XG4gIH1cblxuICBwcml2YXRlIF9pbml0aWFsaXplV1NTKHdzczogV2ViU29ja2V0U2VydmVyKTogdm9pZCB7XG4gICAgdGhpcy5fd3NzID0gd3NzO1xuICAgIHRoaXMuX3dzcy5vbignY29ubmVjdGlvbicsICh3cykgPT4ge1xuICAgICAgd3Mub24oJ21lc3NhZ2UnLCAobWVzc2FnZTogQnVmZmVyKSA9PiB7XG4gICAgICAgIGNvbnN0IG9yaWdpbmFsID0gSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZS5Gcm9tQnVmZmVyKG1lc3NhZ2UpO1xuICAgICAgICB0aGlzLmNiKG9yaWdpbmFsKTtcbiAgICAgICAgLy8gUmVtb3ZlIHRyYW5zZmVyLWVuY29kaW5nLiBXZSBkb24ndCBzdXBwb3J0IGNodW5rZWQuXG4gICAgICAgIGlmICh0aGlzLl9jYWNoZUVuYWJsZWQpIHtcbiAgICAgICAgICB0aGlzLl9jYWNoZS5zZXQob3JpZ2luYWwucmVxdWVzdC5yYXdVcmwsXG4gICAgICAgICAgICBuZXcgQ2FjaGVkSXRlbShvcmlnaW5hbC5yZXF1ZXN0LnJhd1VybCwgb3JpZ2luYWwucmVzcG9uc2UuZ2V0SGVhZGVyKCdjb250ZW50LXR5cGUnKSwgb3JpZ2luYWwucmVzcG9uc2VCb2R5KSk7XG4gICAgICAgIH1cbiAgICAgICAgd3Muc2VuZChvcmlnaW5hbC50b0J1ZmZlcigpKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5pdGlhbGl6ZU1JVE1Qcm94eShtaXRtUHJveHk6IENoaWxkUHJvY2Vzcyk6IHZvaWQge1xuICAgIHRoaXMuX21pdG1Qcm9jZXNzID0gbWl0bVByb3h5O1xuICAgIHRoaXMuX21pdG1Qcm9jZXNzLm9uKCdleGl0JywgKGNvZGUsIHNpZ25hbCkgPT4ge1xuICAgICAgY29uc3QgaW5kZXggPSBNSVRNUHJveHkuX2FjdGl2ZVByb2Nlc3Nlcy5pbmRleE9mKHRoaXMuX21pdG1Qcm9jZXNzKTtcbiAgICAgIGlmIChpbmRleCAhPT0gLTEpIHtcbiAgICAgICAgTUlUTVByb3h5Ll9hY3RpdmVQcm9jZXNzZXMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICAgIH1cbiAgICAgIGlmIChjb2RlICE9PSBudWxsKSB7XG4gICAgICAgIGlmIChjb2RlICE9PSAwKSB7XG4gICAgICAgICAgdGhpcy5fbWl0bUVycm9yID0gbmV3IEVycm9yKGBQcm9jZXNzIGV4aXRlZCB3aXRoIGNvZGUgJHtjb2RlfS5gKTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5fbWl0bUVycm9yID0gbmV3IEVycm9yKGBQcm9jZXNzIGV4aXRlZCBkdWUgdG8gc2lnbmFsICR7c2lnbmFsfS5gKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICB0aGlzLl9taXRtUHJvY2Vzcy5vbignZXJyb3InLCAoZXJyKSA9PiB7XG4gICAgICB0aGlzLl9taXRtRXJyb3IgPSBlcnI7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogUmV0cmlldmVzIHRoZSBnaXZlbiBVUkwgZnJvbSB0aGUgY2FjaGUuXG4gICAqIEBwYXJhbSB1cmxcbiAgICovXG4gIHB1YmxpYyBnZXRGcm9tQ2FjaGUodXJsOiBzdHJpbmcpOiBDYWNoZWRJdGVtIHtcbiAgICByZXR1cm4gdGhpcy5fY2FjaGUuZ2V0KHVybCk7XG4gIH1cblxuICBwdWJsaWMgZm9yRWFjaENhY2hlSXRlbShjYjogKHZhbHVlOiBDYWNoZWRJdGVtLCB1cmw6IHN0cmluZykgPT4gdm9pZCk6IHZvaWQge1xuICAgIHRoaXMuX2NhY2hlLmZvckVhY2goY2IpO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlcXVlc3RzIHRoZSBnaXZlbiBVUkwgZnJvbSB0aGUgcHJveHkuXG4gICAqL1xuICBwdWJsaWMgYXN5bmMgcHJveHlHZXQodXJsU3RyaW5nOiBzdHJpbmcpOiBQcm9taXNlPEhUVFBSZXNwb25zZT4ge1xuICAgIGNvbnN0IHVybCA9IHBhcnNlVVJMKHVybFN0cmluZyk7XG4gICAgY29uc3QgZ2V0ID0gdXJsLnByb3RvY29sID09PSBcImh0dHA6XCIgPyBodHRwR2V0IDogaHR0cHNHZXQ7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEhUVFBSZXNwb25zZT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgY29uc3QgcmVxID0gZ2V0KHtcbiAgICAgICAgdXJsOiB1cmxTdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICBob3N0OiB1cmwuaG9zdFxuICAgICAgICB9LFxuICAgICAgICBob3N0OiAnbG9jYWxob3N0JyxcbiAgICAgICAgcG9ydDogODA4MCxcbiAgICAgICAgcGF0aDogdXJsU3RyaW5nXG4gICAgICB9LCAocmVzKSA9PiB7XG4gICAgICAgIGNvbnN0IGRhdGEgPSBuZXcgQXJyYXk8QnVmZmVyPigpO1xuICAgICAgICByZXMub24oJ2RhdGEnLCAoY2h1bms6IEJ1ZmZlcikgPT4ge1xuICAgICAgICAgIGRhdGEucHVzaChjaHVuayk7XG4gICAgICAgIH0pO1xuICAgICAgICByZXMub24oJ2VuZCcsICgpID0+IHtcbiAgICAgICAgICBjb25zdCBkID0gQnVmZmVyLmNvbmNhdChkYXRhKTtcbiAgICAgICAgICByZXNvbHZlKHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IHJlcy5zdGF0dXNDb2RlLFxuICAgICAgICAgICAgaGVhZGVyczogcmVzLmhlYWRlcnMsXG4gICAgICAgICAgICBib2R5OiBkXG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgICByZXMub25jZSgnZXJyb3InLCByZWplY3QpO1xuICAgICAgfSk7XG4gICAgICByZXEub25jZSgnZXJyb3InLCByZWplY3QpO1xuICAgIH0pO1xuICB9XG5cbiAgcHVibGljIGFzeW5jIHNodXRkb3duKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBjb25zdCBjbG9zZVdTUyA9ICgpID0+IHtcbiAgICAgICAgdGhpcy5fd3NzLmNsb3NlKChlcnIpID0+IHtcbiAgICAgICAgICBpZiAoZXJyKSB7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9O1xuXG4gICAgICBpZiAodGhpcy5fbWl0bVByb2Nlc3MgJiYgdGhpcy5fbWl0bVByb2Nlc3MuY29ubmVjdGVkKSB7XG4gICAgICAgIHRoaXMuX21pdG1Qcm9jZXNzLm9uY2UoJ2V4aXQnLCAoY29kZSwgc2lnbmFsKSA9PiB7XG4gICAgICAgICAgY2xvc2VXU1MoKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHRoaXMuX21pdG1Qcm9jZXNzLmtpbGwoKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNsb3NlV1NTKCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn1cbiJdfQ==