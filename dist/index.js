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
class StashedItem {
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
exports.StashedItem = StashedItem;
/**
 * Class that launches MITM proxy and talks to it via WebSockets.
 */
class MITMProxy {
    constructor(cb) {
        this._stashEnabled = false;
        this._mitmProcess = null;
        this._mitmError = null;
        this._wss = null;
        this._stash = new Map();
        this.cb = cb;
    }
    static Create(cb = nopInterceptor, quiet = false) {
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
                if (!quiet) {
                    console.log(`MITMProxy already running.`);
                }
            }
            catch (e) {
                if (!quiet) {
                    console.log(`MITMProxy not running; starting up mitmproxy.`);
                }
                // Start up MITM process.
                // --anticache means to disable caching, which gets in the way of transparently rewriting content.
                const options = ["--anticache", "-s", path_1.resolve(__dirname, "../scripts/proxy.py")];
                if (quiet) {
                    options.push('-q');
                }
                const mitmProcess = child_process_1.spawn("mitmdump", options, {
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
    // Toggle whether or not mitmproxy-node stashes modified server responses.
    // **Not used for performance**, but enables Node.js code to fetch previous server responses from the proxy.
    get stashEnabled() {
        return this._stashEnabled;
    }
    set stashEnabled(v) {
        if (!v) {
            this._stash.clear();
        }
        this._stashEnabled = v;
    }
    _initializeWSS(wss) {
        this._wss = wss;
        this._wss.on('connection', (ws) => {
            ws.on('message', (message) => {
                const original = InterceptedHTTPMessage.FromBuffer(message);
                this.cb(original);
                // Remove transfer-encoding. We don't support chunked.
                if (this._stashEnabled) {
                    this._stash.set(original.request.rawUrl, new StashedItem(original.request.rawUrl, original.response.getHeader('content-type'), original.responseBody));
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
     * Retrieves the given URL from the stash.
     * @param url
     */
    getFromStash(url) {
        return this._stash.get(url);
    }
    forEachStashItem(cb) {
        this._stash.forEach(cb);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQUFBLDJCQUE2QztBQUM3QyxpREFBa0Q7QUFDbEQsK0JBQTZCO0FBQzdCLDZCQUEyQztBQUMzQywrQkFBb0M7QUFDcEMsaUNBQXNDO0FBQ3RDLDZCQUE2QztBQUU3Qzs7Ozs7R0FLRztBQUNILHFCQUFxQixJQUFZLEVBQUUsVUFBa0IsRUFBRSxFQUFFLFdBQW1CLEdBQUc7SUFDN0UsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQzNDLElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDO1FBQy9CLElBQUksYUFBYSxHQUFHLFFBQVEsQ0FBQztRQUM3QixJQUFJLEtBQUssR0FBaUIsSUFBSSxDQUFDO1FBQy9CLElBQUksTUFBTSxHQUFXLElBQUksQ0FBQztRQUUxQjtZQUNFLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUNwQixLQUFLLEdBQUcsSUFBSSxDQUFDO1lBQ2IsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDO2dCQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUM3QixNQUFNLEdBQUcsSUFBSSxDQUFDO1FBQ2hCLENBQUM7UUFFRDtZQUNFLFlBQVksRUFBRSxDQUFDO1FBQ2pCLENBQUM7UUFFRDtZQUNFLDBCQUEwQixFQUFFLENBQUM7WUFFN0IsRUFBRSxDQUFDLENBQUMsRUFBRSxnQkFBZ0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMzQixNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDO1lBQ3RDLENBQUM7WUFFRCxNQUFNLEdBQUcsc0JBQWdCLENBQUMsSUFBSSxFQUFFLFdBQVcsRUFBRTtnQkFDM0MsMEJBQTBCLEVBQUUsQ0FBQztnQkFDN0IsRUFBRSxDQUFDLENBQUMsZ0JBQWdCLElB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Q2IsQ0FBQztZQUNILENBQUMsQ0FBQyxDQUFDO1FBQ0wsQ0FBQztLQUFBOztBQTVMYywwQkFBZ0IsR0FBbUIsRUFBRSxDQUFDO0FBb0R0Qyx3QkFBYyxHQUFHLEtBQUssQ0FBQztBQXJEeEMsNEJBOExDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHtTZXJ2ZXIgYXMgV2ViU29ja2V0U2VydmVyfSBmcm9tICd3cyc7XG5pbXBvcnQge3NwYXduLCBDaGlsZFByb2Nlc3N9IGZyb20gJ2NoaWxkX3Byb2Nlc3MnO1xuaW1wb3J0IHtyZXNvbHZlfSBmcm9tICdwYXRoJztcbmltcG9ydCB7cGFyc2UgYXMgcGFyc2VVUkwsIFVybH0gZnJvbSAndXJsJztcbmltcG9ydCB7Z2V0IGFzIGh0dHBHZXR9IGZyb20gJ2h0dHAnO1xuaW1wb3J0IHtnZXQgYXMgaHR0cHNHZXR9IGZyb20gJ2h0dHBzJztcbmltcG9ydCB7Y3JlYXRlQ29ubmVjdGlvbiwgU29ja2V0fSBmcm9tICduZXQnO1xuXG4vKipcbiAqIFdhaXQgZm9yIHRoZSBzcGVjaWZpZWQgcG9ydCB0byBvcGVuLlxuICogQHBhcmFtIHBvcnQgVGhlIHBvcnQgdG8gd2F0Y2ggZm9yLlxuICogQHBhcmFtIHJldHJpZXMgVGhlIG51bWJlciBvZiB0aW1lcyB0byByZXRyeSBiZWZvcmUgZ2l2aW5nIHVwLiBEZWZhdWx0cyB0byAxMC5cbiAqIEBwYXJhbSBpbnRlcnZhbCBUaGUgaW50ZXJ2YWwgYmV0d2VlbiByZXRyaWVzLCBpbiBtaWxsaXNlY29uZHMuIERlZmF1bHRzIHRvIDUwMC5cbiAqL1xuZnVuY3Rpb24gd2FpdEZvclBvcnQocG9ydDogbnVtYmVyLCByZXRyaWVzOiBudW1iZXIgPSAxMCwgaW50ZXJ2YWw6IG51bWJlciA9IDUwMCk6IFByb21pc2U8dm9pZD4ge1xuICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgIGxldCByZXRyaWVzUmVtYWluaW5nID0gcmV0cmllcztcbiAgICBsZXQgcmV0cnlJbnRlcnZhbCA9IGludGVydmFsO1xuICAgIGxldCB0aW1lcjogTm9kZUpTLlRpbWVyID0gbnVsbDtcbiAgICBsZXQgc29ja2V0OiBTb2NrZXQgPSBudWxsO1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGltZXIpO1xuICAgICAgdGltZXIgPSBudWxsO1xuICAgICAgaWYgKHNvY2tldCkgc29ja2V0LmRlc3Ryb3koKTtcbiAgICAgIHNvY2tldCA9IG51bGw7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmV0cnkoKSB7XG4gICAgICB0cnlUb0Nvbm5lY3QoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB0cnlUb0Nvbm5lY3QoKSB7XG4gICAgICBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpO1xuXG4gICAgICBpZiAoLS1yZXRyaWVzUmVtYWluaW5nIDwgMCkge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdvdXQgb2YgcmV0cmllcycpKTtcbiAgICAgIH1cblxuICAgICAgc29ja2V0ID0gY3JlYXRlQ29ubmVjdGlvbihwb3J0LCBcImxvY2FsaG9zdFwiLCBmdW5jdGlvbigpIHtcbiAgICAgICAgY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKTtcbiAgICAgICAgaWYgKHJldHJpZXNSZW1haW5pbmcgPj0gMCkgcmVzb2x2ZSgpO1xuICAgICAgfSk7XG5cbiAgICAgIHRpbWVyID0gc2V0VGltZW91dChmdW5jdGlvbigpIHsgcmV0cnkoKTsgfSwgcmV0cnlJbnRlcnZhbCk7XG5cbiAgICAgIHNvY2tldC5vbignZXJyb3InLCBmdW5jdGlvbihlcnIpIHtcbiAgICAgICAgY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKTtcbiAgICAgICAgc2V0VGltZW91dChyZXRyeSwgcmV0cnlJbnRlcnZhbCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB0cnlUb0Nvbm5lY3QoKTtcbiAgfSk7XG59XG5cbi8qKlxuICogRnVuY3Rpb24gdGhhdCBpbnRlcmNlcHRzIGFuZCByZXdyaXRlcyBIVFRQIHJlc3BvbnNlcy5cbiAqL1xuZXhwb3J0IHR5cGUgSW50ZXJjZXB0b3IgPSAobTogSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZSkgPT4gdm9pZDtcblxuLyoqXG4gKiBBbiBpbnRlcmNlcHRvciB0aGF0IGRvZXMgbm90aGluZy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIG5vcEludGVyY2VwdG9yKG06IEludGVyY2VwdGVkSFRUUE1lc3NhZ2UpOiB2b2lkIHt9XG5cbi8qKlxuICogVGhlIGNvcmUgSFRUUCByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBIVFRQUmVzcG9uc2Uge1xuICBzdGF0dXNDb2RlOiBudW1iZXIsXG4gIGhlYWRlcnM6IHtbbmFtZTogc3RyaW5nXTogc3RyaW5nfTtcbiAgYm9keTogQnVmZmVyO1xufVxuXG4vKipcbiAqIE1ldGFkYXRhIGFzc29jaWF0ZWQgd2l0aCBhIHJlcXVlc3QvcmVzcG9uc2UgcGFpci5cbiAqL1xuaW50ZXJmYWNlIEhUVFBNZXNzYWdlTWV0YWRhdGEge1xuICByZXF1ZXN0OiBIVFRQUmVxdWVzdE1ldGFkYXRhO1xuICByZXNwb25zZTogSFRUUFJlc3BvbnNlTWV0YWRhdGE7XG59XG5cbi8qKlxuICogTWV0YWRhdGEgYXNzb2NpYXRlZCB3aXRoIGFuIEhUVFAgcmVxdWVzdC5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBIVFRQUmVxdWVzdE1ldGFkYXRhIHtcbiAgLy8gR0VULCBERUxFVEUsIFBPU1QsICBldGMuXG4gIG1ldGhvZDogc3RyaW5nO1xuICAvLyBUYXJnZXQgVVJMIGZvciB0aGUgcmVxdWVzdC5cbiAgdXJsOiBzdHJpbmc7XG4gIC8vIFRoZSBzZXQgb2YgaGVhZGVycyBmcm9tIHRoZSByZXF1ZXN0LCBhcyBrZXktdmFsdWUgcGFpcnMuXG4gIC8vIFNpbmNlIGhlYWRlciBmaWVsZHMgbWF5IGJlIHJlcGVhdGVkLCB0aGlzIGFycmF5IG1heSBjb250YWluIG11bHRpcGxlIGVudHJpZXMgZm9yIHRoZSBzYW1lIGtleS5cbiAgaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdO1xufVxuXG4vKipcbiAqIE1ldGFkYXRhIGFzc29jaWF0ZWQgd2l0aCBhbiBIVFRQIHJlc3BvbnNlLlxuICovXG5leHBvcnQgaW50ZXJmYWNlIEhUVFBSZXNwb25zZU1ldGFkYXRhIHtcbiAgLy8gVGhlIG51bWVyaWNhbCBzdGF0dXMgY29kZS5cbiAgc3RhdHVzX2NvZGU6IG51bWJlcjtcbiAgLy8gVGhlIHNldCBvZiBoZWFkZXJzIGZyb20gdGhlIHJlc3BvbnNlLCBhcyBrZXktdmFsdWUgcGFpcnMuXG4gIC8vIFNpbmNlIGhlYWRlciBmaWVsZHMgbWF5IGJlIHJlcGVhdGVkLCB0aGlzIGFycmF5IG1heSBjb250YWluIG11bHRpcGxlIGVudHJpZXMgZm9yIHRoZSBzYW1lIGtleS5cbiAgaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdO1xufVxuXG4vKipcbiAqIEFic3RyYWN0IGNsYXNzIHRoYXQgcmVwcmVzZW50cyBIVFRQIGhlYWRlcnMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBBYnN0cmFjdEhUVFBIZWFkZXJzIHtcbiAgcHJpdmF0ZSBfaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdO1xuICAvLyBUaGUgcmF3IGhlYWRlcnMsIGFzIGEgc2VxdWVuY2Ugb2Yga2V5L3ZhbHVlIHBhaXJzLlxuICAvLyBTaW5jZSBoZWFkZXIgZmllbGRzIG1heSBiZSByZXBlYXRlZCwgdGhpcyBhcnJheSBtYXkgY29udGFpbiBtdWx0aXBsZSBlbnRyaWVzIGZvciB0aGUgc2FtZSBrZXkuXG4gIHB1YmxpYyBnZXQgaGVhZGVycygpOiBbc3RyaW5nLCBzdHJpbmddW10ge1xuICAgIHJldHVybiB0aGlzLl9oZWFkZXJzO1xuICB9XG4gIGNvbnN0cnVjdG9yKGhlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXSkge1xuICAgIHRoaXMuX2hlYWRlcnMgPSBoZWFkZXJzO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5kZXhPZkhlYWRlcihuYW1lOiBzdHJpbmcpOiBudW1iZXIge1xuICAgIGNvbnN0IGhlYWRlcnMgPSB0aGlzLmhlYWRlcnM7XG4gICAgY29uc3QgbGVuID0gaGVhZGVycy5sZW5ndGg7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsZW47IGkrKykge1xuICAgICAgaWYgKGhlYWRlcnNbaV1bMF0udG9Mb3dlckNhc2UoKSA9PT0gbmFtZSkge1xuICAgICAgICByZXR1cm4gaTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIC0xO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgdmFsdWUgb2YgdGhlIGdpdmVuIGhlYWRlciBmaWVsZC5cbiAgICogSWYgdGhlcmUgYXJlIG11bHRpcGxlIGZpZWxkcyB3aXRoIHRoYXQgbmFtZSwgdGhpcyBvbmx5IHJldHVybnMgdGhlIGZpcnN0IGZpZWxkJ3MgdmFsdWUhXG4gICAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGhlYWRlciBmaWVsZFxuICAgKi9cbiAgcHVibGljIGdldEhlYWRlcihuYW1lOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIGNvbnN0IGluZGV4ID0gdGhpcy5faW5kZXhPZkhlYWRlcihuYW1lLnRvTG93ZXJDYXNlKCkpO1xuICAgIGlmIChpbmRleCAhPT0gLTEpIHtcbiAgICAgIHJldHVybiB0aGlzLmhlYWRlcnNbaW5kZXhdWzFdO1xuICAgIH1cbiAgICByZXR1cm4gJyc7XG4gIH1cblxuICAvKipcbiAgICogU2V0IHRoZSB2YWx1ZSBvZiB0aGUgZ2l2ZW4gaGVhZGVyIGZpZWxkLiBBc3N1bWVzIHRoYXQgdGhlcmUgaXMgb25seSBvbmUgZmllbGQgd2l0aCB0aGUgZ2l2ZW4gbmFtZS5cbiAgICogSWYgdGhlIGZpZWxkIGRvZXMgbm90IGV4aXN0LCBpdCBhZGRzIGEgbmV3IGZpZWxkIHdpdGggdGhlIG5hbWUgYW5kIHZhbHVlLlxuICAgKiBAcGFyYW0gbmFtZSBOYW1lIG9mIHRoZSBmaWVsZC5cbiAgICogQHBhcmFtIHZhbHVlIE5ldyB2YWx1ZS5cbiAgICovXG4gIHB1YmxpYyBzZXRIZWFkZXIobmFtZTogc3RyaW5nLCB2YWx1ZTogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3QgaW5kZXggPSB0aGlzLl9pbmRleE9mSGVhZGVyKG5hbWUudG9Mb3dlckNhc2UoKSk7XG4gICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgdGhpcy5oZWFkZXJzW2luZGV4XVsxXSA9IHZhbHVlO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmhlYWRlcnMucHVzaChbbmFtZSwgdmFsdWVdKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlcyB0aGUgaGVhZGVyIGZpZWxkIHdpdGggdGhlIGdpdmVuIG5hbWUuIEFzc3VtZXMgdGhhdCB0aGVyZSBpcyBvbmx5IG9uZSBmaWVsZCB3aXRoIHRoZSBnaXZlbiBuYW1lLlxuICAgKiBEb2VzIG5vdGhpbmcgaWYgZmllbGQgZG9lcyBub3QgZXhpc3QuXG4gICAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGZpZWxkLlxuICAgKi9cbiAgcHVibGljIHJlbW92ZUhlYWRlcihuYW1lOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBjb25zdCBpbmRleCA9IHRoaXMuX2luZGV4T2ZIZWFkZXIobmFtZS50b0xvd2VyQ2FzZSgpKTtcbiAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICB0aGlzLmhlYWRlcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlcyBhbGwgaGVhZGVyIGZpZWxkcy5cbiAgICovXG4gIHB1YmxpYyBjbGVhckhlYWRlcnMoKTogdm9pZCB7XG4gICAgdGhpcy5faGVhZGVycyA9IFtdO1xuICB9XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyBhIE1JVE0tZWQgSFRUUCByZXNwb25zZSBmcm9tIGEgc2VydmVyLlxuICovXG5leHBvcnQgY2xhc3MgSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2UgZXh0ZW5kcyBBYnN0cmFjdEhUVFBIZWFkZXJzIHtcbiAgLy8gVGhlIHN0YXR1cyBjb2RlIG9mIHRoZSBIVFRQIHJlc3BvbnNlLlxuICBwdWJsaWMgc3RhdHVzQ29kZTogbnVtYmVyO1xuXG4gIGNvbnN0cnVjdG9yKG1ldGFkYXRhOiBIVFRQUmVzcG9uc2VNZXRhZGF0YSkge1xuICAgIHN1cGVyKG1ldGFkYXRhLmhlYWRlcnMpO1xuICAgIHRoaXMuc3RhdHVzQ29kZSA9IG1ldGFkYXRhLnN0YXR1c19jb2RlO1xuICAgIC8vIFdlIGRvbid0IHN1cHBvcnQgY2h1bmtlZCB0cmFuc2ZlcnMuIFRoZSBwcm94eSBhbHJlYWR5IGRlLWNodW5rcyBpdCBmb3IgdXMuXG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ3RyYW5zZmVyLWVuY29kaW5nJyk7XG4gICAgLy8gTUlUTVByb3h5IGRlY29kZXMgdGhlIGRhdGEgZm9yIHVzLlxuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCdjb250ZW50LWVuY29kaW5nJyk7XG4gICAgLy8gQ1NQIGlzIGJhZCFcbiAgICB0aGlzLnJlbW92ZUhlYWRlcignY29udGVudC1zZWN1cml0eS1wb2xpY3knKTtcbiAgICB0aGlzLnJlbW92ZUhlYWRlcigneC13ZWJraXQtY3NwJyk7XG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ3gtY29udGVudC1zZWN1cml0eS1wb2xpY3knKTtcbiAgfVxuXG4gIHB1YmxpYyB0b0pTT04oKTogSFRUUFJlc3BvbnNlTWV0YWRhdGEge1xuICAgIHJldHVybiB7XG4gICAgICBzdGF0dXNfY29kZTogdGhpcy5zdGF0dXNDb2RlLFxuICAgICAgaGVhZGVyczogdGhpcy5oZWFkZXJzXG4gICAgfTtcbiAgfVxufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYW4gaW50ZXJjZXB0ZWQgSFRUUCByZXF1ZXN0IGZyb20gYSBjbGllbnQuXG4gKi9cbmV4cG9ydCBjbGFzcyBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0IGV4dGVuZHMgQWJzdHJhY3RIVFRQSGVhZGVycyB7XG4gIC8vIEhUVFAgbWV0aG9kIChHRVQvREVMRVRFL2V0YylcbiAgcHVibGljIG1ldGhvZDogc3RyaW5nO1xuICAvLyBUaGUgVVJMIGFzIGEgc3RyaW5nLlxuICBwdWJsaWMgcmF3VXJsOiBzdHJpbmc7XG4gIC8vIFRoZSBVUkwgYXMgYSBVUkwgb2JqZWN0LlxuICBwdWJsaWMgdXJsOiBVcmw7XG5cbiAgY29uc3RydWN0b3IobWV0YWRhdGE6IEhUVFBSZXF1ZXN0TWV0YWRhdGEpIHtcbiAgICBzdXBlcihtZXRhZGF0YS5oZWFkZXJzKTtcbiAgICB0aGlzLm1ldGhvZCA9IG1ldGFkYXRhLm1ldGhvZC50b0xvd2VyQ2FzZSgpO1xuICAgIHRoaXMucmF3VXJsID0gbWV0YWRhdGEudXJsO1xuICAgIHRoaXMudXJsID0gcGFyc2VVUkwodGhpcy5yYXdVcmwpO1xuICB9XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyBhbiBpbnRlcmNlcHRlZCBIVFRQIHJlcXVlc3QvcmVzcG9uc2UgcGFpci5cbiAqL1xuZXhwb3J0IGNsYXNzIEludGVyY2VwdGVkSFRUUE1lc3NhZ2Uge1xuICAvKipcbiAgICogVW5wYWNrIGZyb20gYSBCdWZmZXIgcmVjZWl2ZWQgZnJvbSBNSVRNUHJveHkuXG4gICAqIEBwYXJhbSBiXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIEZyb21CdWZmZXIoYjogQnVmZmVyKTogSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZSB7XG4gICAgY29uc3QgbWV0YWRhdGFTaXplID0gYi5yZWFkSW50MzJMRSgwKTtcbiAgICBjb25zdCByZXF1ZXN0U2l6ZSA9IGIucmVhZEludDMyTEUoNCk7XG4gICAgY29uc3QgcmVzcG9uc2VTaXplID0gYi5yZWFkSW50MzJMRSg4KTtcbiAgICBjb25zdCBtZXRhZGF0YTogSFRUUE1lc3NhZ2VNZXRhZGF0YSA9IEpTT04ucGFyc2UoYi50b1N0cmluZyhcInV0ZjhcIiwgMTIsIDEyICsgbWV0YWRhdGFTaXplKSk7XG4gICAgcmV0dXJuIG5ldyBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlKFxuICAgICAgbmV3IEludGVyY2VwdGVkSFRUUFJlcXVlc3QobWV0YWRhdGEucmVxdWVzdCksXG4gICAgICBuZXcgSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2UobWV0YWRhdGEucmVzcG9uc2UpLFxuICAgICAgYi5zbGljZSgxMiArIG1ldGFkYXRhU2l6ZSwgMTIgKyBtZXRhZGF0YVNpemUgKyByZXF1ZXN0U2l6ZSksXG4gICAgICBiLnNsaWNlKDEyICsgbWV0YWRhdGFTaXplICsgcmVxdWVzdFNpemUsIDEyICsgbWV0YWRhdGFTaXplICsgcmVxdWVzdFNpemUgKyByZXNwb25zZVNpemUpXG4gICAgKTtcbiAgfVxuXG4gIHB1YmxpYyByZWFkb25seSByZXF1ZXN0OiBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0O1xuICBwdWJsaWMgcmVhZG9ubHkgcmVzcG9uc2U6IEludGVyY2VwdGVkSFRUUFJlc3BvbnNlO1xuICAvLyBUaGUgYm9keSBvZiB0aGUgSFRUUCByZXF1ZXN0LlxuICBwdWJsaWMgcmVhZG9ubHkgcmVxdWVzdEJvZHk6IEJ1ZmZlcjtcbiAgLy8gVGhlIGJvZHkgb2YgdGhlIEhUVFAgcmVzcG9uc2UuIFJlYWQtb25seTsgY2hhbmdlIHRoZSByZXNwb25zZSBib2R5IHZpYSBzZXRSZXNwb25zZUJvZHkuXG4gIHB1YmxpYyBnZXQgcmVzcG9uc2VCb2R5KCk6IEJ1ZmZlciB7XG4gICAgcmV0dXJuIHRoaXMuX3Jlc3BvbnNlQm9keTtcbiAgfVxuICBwcml2YXRlIF9yZXNwb25zZUJvZHk6IEJ1ZmZlcjtcbiAgcHJpdmF0ZSBjb25zdHJ1Y3RvcihyZXF1ZXN0OiBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0LCByZXNwb25zZTogSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2UsIHJlcXVlc3RCb2R5OiBCdWZmZXIsIHJlc3BvbnNlQm9keTogQnVmZmVyKSB7XG4gICAgdGhpcy5yZXF1ZXN0ID0gcmVxdWVzdDtcbiAgICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gICAgdGhpcy5yZXF1ZXN0Qm9keSA9IHJlcXVlc3RCb2R5O1xuICAgIHRoaXMuX3Jlc3BvbnNlQm9keSA9IHJlc3BvbnNlQm9keTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGFuZ2VzIHRoZSBib2R5IG9mIHRoZSBIVFRQIHJlc3BvbnNlLiBBcHByb3ByaWF0ZWx5IHVwZGF0ZXMgY29udGVudC1sZW5ndGguXG4gICAqIEBwYXJhbSBiIFRoZSBuZXcgYm9keSBjb250ZW50cy5cbiAgICovXG4gIHB1YmxpYyBzZXRSZXNwb25zZUJvZHkoYjogQnVmZmVyKSB7XG4gICAgdGhpcy5fcmVzcG9uc2VCb2R5ID0gYjtcbiAgICAvLyBVcGRhdGUgY29udGVudC1sZW5ndGguXG4gICAgdGhpcy5yZXNwb25zZS5zZXRIZWFkZXIoJ2NvbnRlbnQtbGVuZ3RoJywgYCR7Yi5sZW5ndGh9YCk7XG4gICAgLy8gVE9ETzogQ29udGVudC1lbmNvZGluZz9cbiAgfVxuXG4gIC8qKlxuICAgKiBQYWNrIGludG8gYSBidWZmZXIgZm9yIHRyYW5zbWlzc2lvbiB0byBNSVRNUHJveHkuXG4gICAqL1xuICBwdWJsaWMgdG9CdWZmZXIoKTogQnVmZmVyIHtcbiAgICBjb25zdCBtZXRhZGF0YSA9IEJ1ZmZlci5mcm9tKEpTT04uc3RyaW5naWZ5KHRoaXMucmVzcG9uc2UpLCAndXRmOCcpO1xuICAgIGNvbnN0IG1ldGFkYXRhTGVuZ3RoID0gbWV0YWRhdGEubGVuZ3RoO1xuICAgIGNvbnN0IHJlc3BvbnNlTGVuZ3RoID0gdGhpcy5fcmVzcG9uc2VCb2R5Lmxlbmd0aFxuICAgIGNvbnN0IHJ2ID0gQnVmZmVyLmFsbG9jKDggKyBtZXRhZGF0YUxlbmd0aCArIHJlc3BvbnNlTGVuZ3RoKTtcbiAgICBydi53cml0ZUludDMyTEUobWV0YWRhdGFMZW5ndGgsIDApO1xuICAgIHJ2LndyaXRlSW50MzJMRShyZXNwb25zZUxlbmd0aCwgNCk7XG4gICAgbWV0YWRhdGEuY29weShydiwgOCk7XG4gICAgdGhpcy5fcmVzcG9uc2VCb2R5LmNvcHkocnYsIDggKyBtZXRhZGF0YUxlbmd0aCk7XG4gICAgcmV0dXJuIHJ2O1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTdGFzaGVkSXRlbSB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHB1YmxpYyByZWFkb25seSByYXdVcmw6IHN0cmluZyxcbiAgICBwdWJsaWMgcmVhZG9ubHkgbWltZVR5cGU6IHN0cmluZyxcbiAgICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogQnVmZmVyKSB7fVxuXG4gIHB1YmxpYyBnZXQgc2hvcnRNaW1lVHlwZSgpOiBzdHJpbmcge1xuICAgIGxldCBtaW1lID0gdGhpcy5taW1lVHlwZS50b0xvd2VyQ2FzZSgpO1xuICAgIGlmIChtaW1lLmluZGV4T2YoXCI7XCIpICE9PSAtMSkge1xuICAgICAgbWltZSA9IG1pbWUuc2xpY2UoMCwgbWltZS5pbmRleE9mKFwiO1wiKSk7XG4gICAgfVxuICAgIHJldHVybiBtaW1lO1xuICB9XG5cbiAgcHVibGljIGdldCBpc0h0bWwoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMuc2hvcnRNaW1lVHlwZSA9PT0gXCJ0ZXh0L2h0bWxcIjtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgaXNKYXZhU2NyaXB0KCk6IGJvb2xlYW4ge1xuICAgIHN3aXRjaCh0aGlzLnNob3J0TWltZVR5cGUpIHtcbiAgICAgIGNhc2UgJ3RleHQvamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICdhcHBsaWNhdGlvbi9qYXZhc2NyaXB0JzpcbiAgICAgIGNhc2UgJ3RleHQveC1qYXZhc2NyaXB0JzpcbiAgICAgIGNhc2UgJ2FwcGxpY2F0aW9uL3gtamF2YXNjcmlwdCc6XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxufVxuXG4vKipcbiAqIENsYXNzIHRoYXQgbGF1bmNoZXMgTUlUTSBwcm94eSBhbmQgdGFsa3MgdG8gaXQgdmlhIFdlYlNvY2tldHMuXG4gKi9cbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE1JVE1Qcm94eSB7XG4gIHByaXZhdGUgc3RhdGljIF9hY3RpdmVQcm9jZXNzZXM6IENoaWxkUHJvY2Vzc1tdID0gW107XG5cbiAgcHVibGljIHN0YXRpYyBhc3luYyBDcmVhdGUoY2I6IEludGVyY2VwdG9yID0gbm9wSW50ZXJjZXB0b3IsIHF1aWV0OiBib29sZWFuID0gZmFsc2UpOiBQcm9taXNlPE1JVE1Qcm94eT4ge1xuICAgIC8vIENvbnN0cnVjdCBXZWJTb2NrZXQgc2VydmVyLCBhbmQgd2FpdCBmb3IgaXQgdG8gYmVnaW4gbGlzdGVuaW5nLlxuICAgIGNvbnN0IHdzcyA9IG5ldyBXZWJTb2NrZXRTZXJ2ZXIoeyBwb3J0OiA4NzY1IH0pO1xuICAgIGNvbnN0IHByb3h5Q29ubmVjdGVkID0gbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgd3NzLm9uY2UoJ2Nvbm5lY3Rpb24nLCAoKSA9PiB7XG4gICAgICAgIHJlc29sdmUoKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuICAgIGNvbnN0IG1wID0gbmV3IE1JVE1Qcm94eShjYik7XG4gICAgLy8gU2V0IHVwIFdTUyBjYWxsYmFja3MgYmVmb3JlIE1JVE1Qcm94eSBjb25uZWN0cy5cbiAgICBtcC5faW5pdGlhbGl6ZVdTUyh3c3MpO1xuICAgIGF3YWl0IG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHdzcy5vbmNlKCdsaXN0ZW5pbmcnLCAoKSA9PiB7XG4gICAgICAgIHdzcy5yZW1vdmVMaXN0ZW5lcignZXJyb3InLCByZWplY3QpO1xuICAgICAgICByZXNvbHZlKCk7XG4gICAgICB9KTtcbiAgICAgIHdzcy5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgfSk7XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgd2FpdEZvclBvcnQoODA4MCwgMSk7XG4gICAgICBpZiAoIXF1aWV0KSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBNSVRNUHJveHkgYWxyZWFkeSBydW5uaW5nLmApO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGlmICghcXVpZXQpIHtcbiAgICAgICAgY29uc29sZS5sb2coYE1JVE1Qcm94eSBub3QgcnVubmluZzsgc3RhcnRpbmcgdXAgbWl0bXByb3h5LmApO1xuICAgICAgfVxuICAgICAgLy8gU3RhcnQgdXAgTUlUTSBwcm9jZXNzLlxuICAgICAgLy8gLS1hbnRpY2FjaGUgbWVhbnMgdG8gZGlzYWJsZSBjYWNoaW5nLCB3aGljaCBnZXRzIGluIHRoZSB3YXkgb2YgdHJhbnNwYXJlbnRseSByZXdyaXRpbmcgY29udGVudC5cbiAgICAgIGNvbnN0IG9wdGlvbnMgPSBbXCItLWFudGljYWNoZVwiLCBcIi1zXCIsIHJlc29sdmUoX19kaXJuYW1lLCBcIi4uL3NjcmlwdHMvcHJveHkucHlcIildO1xuICAgICAgaWYgKHF1aWV0KSB7XG4gICAgICAgIG9wdGlvbnMucHVzaCgnLXEnKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IG1pdG1Qcm9jZXNzID0gc3Bhd24oXCJtaXRtZHVtcFwiLCBvcHRpb25zLCB7XG4gICAgICAgIHN0ZGlvOiAnaW5oZXJpdCdcbiAgICAgIH0pO1xuICAgICAgaWYgKE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLnB1c2gobWl0bVByb2Nlc3MpID09PSAxKSB7XG4gICAgICAgIHByb2Nlc3Mub24oJ1NJR0lOVCcsIE1JVE1Qcm94eS5fY2xlYW51cCk7XG4gICAgICAgIHByb2Nlc3Mub24oJ2V4aXQnLCBNSVRNUHJveHkuX2NsZWFudXApO1xuICAgICAgfVxuICAgICAgbXAuX2luaXRpYWxpemVNSVRNUHJveHkobWl0bVByb2Nlc3MpO1xuICAgICAgLy8gV2FpdCBmb3IgcG9ydCA4MDgwIHRvIGNvbWUgb25saW5lLlxuICAgICAgYXdhaXQgd2FpdEZvclBvcnQoODA4MCk7XG4gICAgfVxuICAgIGF3YWl0IHByb3h5Q29ubmVjdGVkO1xuXG4gICAgcmV0dXJuIG1wO1xuICB9XG5cbiAgcHJpdmF0ZSBzdGF0aWMgX2NsZWFudXBDYWxsZWQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzdGF0aWMgX2NsZWFudXAoKTogdm9pZCB7XG4gICAgaWYgKE1JVE1Qcm94eS5fY2xlYW51cENhbGxlZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBNSVRNUHJveHkuX2NsZWFudXBDYWxsZWQgPSB0cnVlO1xuICAgIE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLmZvckVhY2goKHApID0+IHtcbiAgICAgIHAua2lsbCgnU0lHS0lMTCcpO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3Rhc2hFbmFibGVkOiBib29sZWFuID0gZmFsc2U7XG4gIC8vIFRvZ2dsZSB3aGV0aGVyIG9yIG5vdCBtaXRtcHJveHktbm9kZSBzdGFzaGVzIG1vZGlmaWVkIHNlcnZlciByZXNwb25zZXMuXG4gIC8vICoqTm90IHVzZWQgZm9yIHBlcmZvcm1hbmNlKiosIGJ1dCBlbmFibGVzIE5vZGUuanMgY29kZSB0byBmZXRjaCBwcmV2aW91cyBzZXJ2ZXIgcmVzcG9uc2VzIGZyb20gdGhlIHByb3h5LlxuICBwdWJsaWMgZ2V0IHN0YXNoRW5hYmxlZCgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gdGhpcy5fc3Rhc2hFbmFibGVkO1xuICB9XG4gIHB1YmxpYyBzZXQgc3Rhc2hFbmFibGVkKHY6IGJvb2xlYW4pIHtcbiAgICBpZiAoIXYpIHtcbiAgICAgIHRoaXMuX3N0YXNoLmNsZWFyKCk7XG4gICAgfVxuICAgIHRoaXMuX3N0YXNoRW5hYmxlZCA9IHY7XG4gIH1cbiAgcHJpdmF0ZSBfbWl0bVByb2Nlc3M6IENoaWxkUHJvY2VzcyA9IG51bGw7XG4gIHByaXZhdGUgX21pdG1FcnJvcjogRXJyb3IgPSBudWxsO1xuICBwcml2YXRlIF93c3M6IFdlYlNvY2tldFNlcnZlciA9IG51bGw7XG4gIHB1YmxpYyBjYjogSW50ZXJjZXB0b3I7XG4gIHByaXZhdGUgX3N0YXNoID0gbmV3IE1hcDxzdHJpbmcsIFN0YXNoZWRJdGVtPigpO1xuXG4gIHByaXZhdGUgY29uc3RydWN0b3IoY2I6IEludGVyY2VwdG9yKSB7XG4gICAgdGhpcy5jYiA9IGNiO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5pdGlhbGl6ZVdTUyh3c3M6IFdlYlNvY2tldFNlcnZlcik6IHZvaWQge1xuICAgIHRoaXMuX3dzcyA9IHdzcztcbiAgICB0aGlzLl93c3Mub24oJ2Nvbm5lY3Rpb24nLCAod3MpID0+IHtcbiAgICAgIHdzLm9uKCdtZXNzYWdlJywgKG1lc3NhZ2U6IEJ1ZmZlcikgPT4ge1xuICAgICAgICBjb25zdCBvcmlnaW5hbCA9IEludGVyY2VwdGVkSFRUUE1lc3NhZ2UuRnJvbUJ1ZmZlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jYihvcmlnaW5hbCk7XG4gICAgICAgIC8vIFJlbW92ZSB0cmFuc2Zlci1lbmNvZGluZy4gV2UgZG9uJ3Qgc3VwcG9ydCBjaHVua2VkLlxuICAgICAgICBpZiAodGhpcy5fc3Rhc2hFbmFibGVkKSB7XG4gICAgICAgICAgdGhpcy5fc3Rhc2guc2V0KG9yaWdpbmFsLnJlcXVlc3QucmF3VXJsLFxuICAgICAgICAgICAgbmV3IFN0YXNoZWRJdGVtKG9yaWdpbmFsLnJlcXVlc3QucmF3VXJsLCBvcmlnaW5hbC5yZXNwb25zZS5nZXRIZWFkZXIoJ2NvbnRlbnQtdHlwZScpLCBvcmlnaW5hbC5yZXNwb25zZUJvZHkpKTtcbiAgICAgICAgfVxuICAgICAgICB3cy5zZW5kKG9yaWdpbmFsLnRvQnVmZmVyKCkpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9pbml0aWFsaXplTUlUTVByb3h5KG1pdG1Qcm94eTogQ2hpbGRQcm9jZXNzKTogdm9pZCB7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3MgPSBtaXRtUHJveHk7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3Mub24oJ2V4aXQnLCAoY29kZSwgc2lnbmFsKSA9PiB7XG4gICAgICBjb25zdCBpbmRleCA9IE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLmluZGV4T2YodGhpcy5fbWl0bVByb2Nlc3MpO1xuICAgICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgICBNSVRNUHJveHkuX2FjdGl2ZVByb2Nlc3Nlcy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgICAgfVxuICAgICAgaWYgKGNvZGUgIT09IG51bGwpIHtcbiAgICAgICAgaWYgKGNvZGUgIT09IDApIHtcbiAgICAgICAgICB0aGlzLl9taXRtRXJyb3IgPSBuZXcgRXJyb3IoYFByb2Nlc3MgZXhpdGVkIHdpdGggY29kZSAke2NvZGV9LmApO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9taXRtRXJyb3IgPSBuZXcgRXJyb3IoYFByb2Nlc3MgZXhpdGVkIGR1ZSB0byBzaWduYWwgJHtzaWduYWx9LmApO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHRoaXMuX21pdG1Qcm9jZXNzLm9uKCdlcnJvcicsIChlcnIpID0+IHtcbiAgICAgIHRoaXMuX21pdG1FcnJvciA9IGVycjtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZXMgdGhlIGdpdmVuIFVSTCBmcm9tIHRoZSBzdGFzaC5cbiAgICogQHBhcmFtIHVybFxuICAgKi9cbiAgcHVibGljIGdldEZyb21TdGFzaCh1cmw6IHN0cmluZyk6IFN0YXNoZWRJdGVtIHtcbiAgICByZXR1cm4gdGhpcy5fc3Rhc2guZ2V0KHVybCk7XG4gIH1cblxuICBwdWJsaWMgZm9yRWFjaFN0YXNoSXRlbShjYjogKHZhbHVlOiBTdGFzaGVkSXRlbSwgdXJsOiBzdHJpbmcpID0+IHZvaWQpOiB2b2lkIHtcbiAgICB0aGlzLl9zdGFzaC5mb3JFYWNoKGNiKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXF1ZXN0cyB0aGUgZ2l2ZW4gVVJMIGZyb20gdGhlIHByb3h5LlxuICAgKi9cbiAgcHVibGljIGFzeW5jIHByb3h5R2V0KHVybFN0cmluZzogc3RyaW5nKTogUHJvbWlzZTxIVFRQUmVzcG9uc2U+IHtcbiAgICBjb25zdCB1cmwgPSBwYXJzZVVSTCh1cmxTdHJpbmcpO1xuICAgIGNvbnN0IGdldCA9IHVybC5wcm90b2NvbCA9PT0gXCJodHRwOlwiID8gaHR0cEdldCA6IGh0dHBzR2V0O1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxIVFRQUmVzcG9uc2U+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IHJlcSA9IGdldCh7XG4gICAgICAgIHVybDogdXJsU3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgaG9zdDogdXJsLmhvc3RcbiAgICAgICAgfSxcbiAgICAgICAgaG9zdDogJ2xvY2FsaG9zdCcsXG4gICAgICAgIHBvcnQ6IDgwODAsXG4gICAgICAgIHBhdGg6IHVybFN0cmluZ1xuICAgICAgfSwgKHJlcykgPT4ge1xuICAgICAgICBjb25zdCBkYXRhID0gbmV3IEFycmF5PEJ1ZmZlcj4oKTtcbiAgICAgICAgcmVzLm9uKCdkYXRhJywgKGNodW5rOiBCdWZmZXIpID0+IHtcbiAgICAgICAgICBkYXRhLnB1c2goY2h1bmspO1xuICAgICAgICB9KTtcbiAgICAgICAgcmVzLm9uKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgICAgY29uc3QgZCA9IEJ1ZmZlci5jb25jYXQoZGF0YSk7XG4gICAgICAgICAgcmVzb2x2ZSh7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiByZXMuc3RhdHVzQ29kZSxcbiAgICAgICAgICAgIGhlYWRlcnM6IHJlcy5oZWFkZXJzLFxuICAgICAgICAgICAgYm9keTogZFxuICAgICAgICAgIH0gYXMgSFRUUFJlc3BvbnNlKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJlcy5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgICB9KTtcbiAgICAgIHJlcS5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgfSk7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgc2h1dGRvd24oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IGNsb3NlV1NTID0gKCkgPT4ge1xuICAgICAgICB0aGlzLl93c3MuY2xvc2UoKGVycikgPT4ge1xuICAgICAgICAgIGlmIChlcnIpIHtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH07XG5cbiAgICAgIGlmICh0aGlzLl9taXRtUHJvY2VzcyAmJiB0aGlzLl9taXRtUHJvY2Vzcy5jb25uZWN0ZWQpIHtcbiAgICAgICAgdGhpcy5fbWl0bVByb2Nlc3Mub25jZSgnZXhpdCcsIChjb2RlLCBzaWduYWwpID0+IHtcbiAgICAgICAgICBjbG9zZVdTUygpO1xuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5fbWl0bVByb2Nlc3Mua2lsbCgpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY2xvc2VXU1MoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufVxuIl19