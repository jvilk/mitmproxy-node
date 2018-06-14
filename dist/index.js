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
function defaultStashFilter(url, item) {
    return item.isJavaScript || item.isHtml;
}
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
        this._stashFilter = defaultStashFilter;
        this.cb = cb;
    }
    /**
     * Creates a new MITMProxy instance.
     * @param cb Called with intercepted HTTP requests / responses.
     * @param interceptPaths List of paths to completely intercept without sending to the server (e.g. ['/eval'])
     * @param quiet If true, do not print debugging messages (defaults to 'true').
     */
    static Create(cb = nopInterceptor, interceptPaths = [], quiet = true) {
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
                    const scriptArgs = interceptPaths.length > 0 ? ["--set", `intercept=${interceptPaths.join(",")}`] : [];
                    const options = ["--anticache", "-s", path_1.resolve(__dirname, `../scripts/proxy.py`)].concat(scriptArgs);
                    if (quiet) {
                        options.push('-q');
                    }
                    const mitmProcess = child_process_1.spawn("mitmdump", options, {
                        stdio: 'inherit'
                    });
                    const mitmProxyExited = new Promise((_, reject) => {
                        mitmProcess.once('error', reject);
                        mitmProcess.once('exit', reject);
                    });
                    if (MITMProxy._activeProcesses.push(mitmProcess) === 1) {
                        process.on('SIGINT', MITMProxy._cleanup);
                        process.on('exit', MITMProxy._cleanup);
                    }
                    mp._initializeMITMProxy(mitmProcess);
                    // Wait for port 8080 to come online.
                    const waitingForPort = waitForPort(8080);
                    try {
                        // Fails if mitmproxy exits before port becomes available.
                        yield Promise.race([mitmProxyExited, waitingForPort]);
                    }
                    catch (e) {
                        if (e && typeof (e) === 'object' && e.code === "ENOENT") {
                            throw new Error(`mitmdump, which is an executable that ships with mitmproxy, is not on your PATH. Please ensure that you can run mitmdump --version successfully from your command line.`);
                        }
                        else {
                            throw new Error(`Unable to start mitmproxy: ${e}`);
                        }
                    }
                }
                yield proxyConnected;
            }
            catch (e) {
                yield new Promise((resolve) => wss.close(resolve));
                throw e;
            }
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
    get stashFilter() {
        return this._stashFilter;
    }
    set stashFilter(value) {
        if (typeof (value) === 'function') {
            this._stashFilter = value;
        }
        else if (value === null) {
            this._stashFilter = defaultStashFilter;
        }
        else {
            throw new Error(`Invalid stash filter: Expected a function.`);
        }
    }
    _initializeWSS(wss) {
        this._wss = wss;
        this._wss.on('connection', (ws) => {
            ws.on('message', (message) => __awaiter(this, void 0, void 0, function* () {
                const original = InterceptedHTTPMessage.FromBuffer(message);
                const rv = this.cb(original);
                if (rv && typeof (rv) === 'object' && rv.then) {
                    yield rv;
                }
                // Remove transfer-encoding. We don't support chunked.
                if (this._stashEnabled) {
                    const item = new StashedItem(original.request.rawUrl, original.response.getHeader('content-type'), original.responseBody);
                    if (this._stashFilter(original.request.rawUrl, item)) {
                        this._stash.set(original.request.rawUrl, item);
                    }
                }
                ws.send(original.toBuffer());
            }));
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
                if (this._mitmProcess && !this._mitmProcess.killed) {
                    this._mitmProcess.once('exit', (code, signal) => {
                        closeWSS();
                    });
                    this._mitmProcess.kill('SIGTERM');
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQUFBLDJCQUE2QztBQUM3QyxpREFBa0Q7QUFDbEQsK0JBQTZCO0FBQzdCLDZCQUEyQztBQUMzQywrQkFBb0M7QUFDcEMsaUNBQXNDO0FBQ3RDLDZCQUE2QztBQUU3Qzs7Ozs7R0FLRztBQUNILHFCQUFxQixJQUFZLEVBQUUsVUFBa0IsRUFBRSxFQUFFLFdBQW1CLEdBQUc7SUFDN0UsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQzNDLElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDO1FBQy9CLElBQUksYUFBYSxHQUFHLFFBQVEsQ0FBQztRQUM3QixJQUFJLEtBQUssR0FBaUIsSUFBSSxDQUFDO1FBQy9CLElBQUksTUFBTSxHQUFXLElBQUksQ0FBQztRQUUxQjtZQUNFLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUNwQixLQUFLLEdBQUcsSUFBSSxDQUFDO1lBQ2IsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDO2dCQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUM3QixNQUFNLEdBQUcsSUFBSSxDQUFDO1FBQ2hCLENBQUM7UUFFRDtZQUNFLFlBQVksRUFBRSxDQUFDO1FBQ2pCLENBQUM7UUFFRDtZQUNFLDBCQUEwQixFQUFFLENBQUM7WUFFN0IsRUFBRSxDQUFDLENBQUMsRUFBRSxnQkFBZ0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMzQixNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDO1lBQ3RDLENBQUM7WUFFRCxNQUFNLEdBQUcsc0JBQWdCLENBQUMsSUFBSSxFQUFFLFdBQVcsRUFBRTtnQkFDM0MsMEJBQTBCLEVBQUUsQ0FBQztnQkFDN0IsRUFBRSxDQUFDLENBQUMsZ0JBQWdCLElB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QUM7b0JBQ04sUUFBUSxFQUFFLENBQUM7Z0JBQ2IsQ0FBQztZQUNILENBQUMsQ0FBQyxDQUFDO1FBQ0wsQ0FBQztLQUFBOztBQXhPYywwQkFBZ0IsR0FBbUIsRUFBRSxDQUFDO0FBOEV0Qyx3QkFBYyxHQUFHLEtBQUssQ0FBQztBQS9FeEMsNEJBME9DIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHtTZXJ2ZXIgYXMgV2ViU29ja2V0U2VydmVyfSBmcm9tICd3cyc7XG5pbXBvcnQge3NwYXduLCBDaGlsZFByb2Nlc3N9IGZyb20gJ2NoaWxkX3Byb2Nlc3MnO1xuaW1wb3J0IHtyZXNvbHZlfSBmcm9tICdwYXRoJztcbmltcG9ydCB7cGFyc2UgYXMgcGFyc2VVUkwsIFVybH0gZnJvbSAndXJsJztcbmltcG9ydCB7Z2V0IGFzIGh0dHBHZXR9IGZyb20gJ2h0dHAnO1xuaW1wb3J0IHtnZXQgYXMgaHR0cHNHZXR9IGZyb20gJ2h0dHBzJztcbmltcG9ydCB7Y3JlYXRlQ29ubmVjdGlvbiwgU29ja2V0fSBmcm9tICduZXQnO1xuXG4vKipcbiAqIFdhaXQgZm9yIHRoZSBzcGVjaWZpZWQgcG9ydCB0byBvcGVuLlxuICogQHBhcmFtIHBvcnQgVGhlIHBvcnQgdG8gd2F0Y2ggZm9yLlxuICogQHBhcmFtIHJldHJpZXMgVGhlIG51bWJlciBvZiB0aW1lcyB0byByZXRyeSBiZWZvcmUgZ2l2aW5nIHVwLiBEZWZhdWx0cyB0byAxMC5cbiAqIEBwYXJhbSBpbnRlcnZhbCBUaGUgaW50ZXJ2YWwgYmV0d2VlbiByZXRyaWVzLCBpbiBtaWxsaXNlY29uZHMuIERlZmF1bHRzIHRvIDUwMC5cbiAqL1xuZnVuY3Rpb24gd2FpdEZvclBvcnQocG9ydDogbnVtYmVyLCByZXRyaWVzOiBudW1iZXIgPSAxMCwgaW50ZXJ2YWw6IG51bWJlciA9IDUwMCk6IFByb21pc2U8dm9pZD4ge1xuICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgIGxldCByZXRyaWVzUmVtYWluaW5nID0gcmV0cmllcztcbiAgICBsZXQgcmV0cnlJbnRlcnZhbCA9IGludGVydmFsO1xuICAgIGxldCB0aW1lcjogTm9kZUpTLlRpbWVyID0gbnVsbDtcbiAgICBsZXQgc29ja2V0OiBTb2NrZXQgPSBudWxsO1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGltZXIpO1xuICAgICAgdGltZXIgPSBudWxsO1xuICAgICAgaWYgKHNvY2tldCkgc29ja2V0LmRlc3Ryb3koKTtcbiAgICAgIHNvY2tldCA9IG51bGw7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmV0cnkoKSB7XG4gICAgICB0cnlUb0Nvbm5lY3QoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB0cnlUb0Nvbm5lY3QoKSB7XG4gICAgICBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpO1xuXG4gICAgICBpZiAoLS1yZXRyaWVzUmVtYWluaW5nIDwgMCkge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdvdXQgb2YgcmV0cmllcycpKTtcbiAgICAgIH1cblxuICAgICAgc29ja2V0ID0gY3JlYXRlQ29ubmVjdGlvbihwb3J0LCBcImxvY2FsaG9zdFwiLCBmdW5jdGlvbigpIHtcbiAgICAgICAgY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKTtcbiAgICAgICAgaWYgKHJldHJpZXNSZW1haW5pbmcgPj0gMCkgcmVzb2x2ZSgpO1xuICAgICAgfSk7XG5cbiAgICAgIHRpbWVyID0gc2V0VGltZW91dChmdW5jdGlvbigpIHsgcmV0cnkoKTsgfSwgcmV0cnlJbnRlcnZhbCk7XG5cbiAgICAgIHNvY2tldC5vbignZXJyb3InLCBmdW5jdGlvbihlcnIpIHtcbiAgICAgICAgY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKTtcbiAgICAgICAgc2V0VGltZW91dChyZXRyeSwgcmV0cnlJbnRlcnZhbCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB0cnlUb0Nvbm5lY3QoKTtcbiAgfSk7XG59XG5cbi8qKlxuICogRnVuY3Rpb24gdGhhdCBpbnRlcmNlcHRzIGFuZCByZXdyaXRlcyBIVFRQIHJlc3BvbnNlcy5cbiAqL1xuZXhwb3J0IHR5cGUgSW50ZXJjZXB0b3IgPSAobTogSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZSkgPT4gdm9pZCB8IFByb21pc2U8dm9pZD47XG5cbi8qKlxuICogQW4gaW50ZXJjZXB0b3IgdGhhdCBkb2VzIG5vdGhpbmcuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBub3BJbnRlcmNlcHRvcihtOiBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlKTogdm9pZCB7fVxuXG4vKipcbiAqIFRoZSBjb3JlIEhUVFAgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSFRUUFJlc3BvbnNlIHtcbiAgc3RhdHVzQ29kZTogbnVtYmVyLFxuICBoZWFkZXJzOiB7W25hbWU6IHN0cmluZ106IHN0cmluZ307XG4gIGJvZHk6IEJ1ZmZlcjtcbn1cblxuLyoqXG4gKiBNZXRhZGF0YSBhc3NvY2lhdGVkIHdpdGggYSByZXF1ZXN0L3Jlc3BvbnNlIHBhaXIuXG4gKi9cbmludGVyZmFjZSBIVFRQTWVzc2FnZU1ldGFkYXRhIHtcbiAgcmVxdWVzdDogSFRUUFJlcXVlc3RNZXRhZGF0YTtcbiAgcmVzcG9uc2U6IEhUVFBSZXNwb25zZU1ldGFkYXRhO1xufVxuXG4vKipcbiAqIE1ldGFkYXRhIGFzc29jaWF0ZWQgd2l0aCBhbiBIVFRQIHJlcXVlc3QuXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSFRUUFJlcXVlc3RNZXRhZGF0YSB7XG4gIC8vIEdFVCwgREVMRVRFLCBQT1NULCAgZXRjLlxuICBtZXRob2Q6IHN0cmluZztcbiAgLy8gVGFyZ2V0IFVSTCBmb3IgdGhlIHJlcXVlc3QuXG4gIHVybDogc3RyaW5nO1xuICAvLyBUaGUgc2V0IG9mIGhlYWRlcnMgZnJvbSB0aGUgcmVxdWVzdCwgYXMga2V5LXZhbHVlIHBhaXJzLlxuICAvLyBTaW5jZSBoZWFkZXIgZmllbGRzIG1heSBiZSByZXBlYXRlZCwgdGhpcyBhcnJheSBtYXkgY29udGFpbiBtdWx0aXBsZSBlbnRyaWVzIGZvciB0aGUgc2FtZSBrZXkuXG4gIGhlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXTtcbn1cblxuLyoqXG4gKiBNZXRhZGF0YSBhc3NvY2lhdGVkIHdpdGggYW4gSFRUUCByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBIVFRQUmVzcG9uc2VNZXRhZGF0YSB7XG4gIC8vIFRoZSBudW1lcmljYWwgc3RhdHVzIGNvZGUuXG4gIHN0YXR1c19jb2RlOiBudW1iZXI7XG4gIC8vIFRoZSBzZXQgb2YgaGVhZGVycyBmcm9tIHRoZSByZXNwb25zZSwgYXMga2V5LXZhbHVlIHBhaXJzLlxuICAvLyBTaW5jZSBoZWFkZXIgZmllbGRzIG1heSBiZSByZXBlYXRlZCwgdGhpcyBhcnJheSBtYXkgY29udGFpbiBtdWx0aXBsZSBlbnRyaWVzIGZvciB0aGUgc2FtZSBrZXkuXG4gIGhlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXTtcbn1cblxuLyoqXG4gKiBBYnN0cmFjdCBjbGFzcyB0aGF0IHJlcHJlc2VudHMgSFRUUCBoZWFkZXJzLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQWJzdHJhY3RIVFRQSGVhZGVycyB7XG4gIHByaXZhdGUgX2hlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXTtcbiAgLy8gVGhlIHJhdyBoZWFkZXJzLCBhcyBhIHNlcXVlbmNlIG9mIGtleS92YWx1ZSBwYWlycy5cbiAgLy8gU2luY2UgaGVhZGVyIGZpZWxkcyBtYXkgYmUgcmVwZWF0ZWQsIHRoaXMgYXJyYXkgbWF5IGNvbnRhaW4gbXVsdGlwbGUgZW50cmllcyBmb3IgdGhlIHNhbWUga2V5LlxuICBwdWJsaWMgZ2V0IGhlYWRlcnMoKTogW3N0cmluZywgc3RyaW5nXVtdIHtcbiAgICByZXR1cm4gdGhpcy5faGVhZGVycztcbiAgfVxuICBjb25zdHJ1Y3RvcihoZWFkZXJzOiBbc3RyaW5nLCBzdHJpbmddW10pIHtcbiAgICB0aGlzLl9oZWFkZXJzID0gaGVhZGVycztcbiAgfVxuXG4gIHByaXZhdGUgX2luZGV4T2ZIZWFkZXIobmFtZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICBjb25zdCBoZWFkZXJzID0gdGhpcy5oZWFkZXJzO1xuICAgIGNvbnN0IGxlbiA9IGhlYWRlcnMubGVuZ3RoO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIGlmIChoZWFkZXJzW2ldWzBdLnRvTG93ZXJDYXNlKCkgPT09IG5hbWUpIHtcbiAgICAgICAgcmV0dXJuIGk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiAtMTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIHZhbHVlIG9mIHRoZSBnaXZlbiBoZWFkZXIgZmllbGQuXG4gICAqIElmIHRoZXJlIGFyZSBtdWx0aXBsZSBmaWVsZHMgd2l0aCB0aGF0IG5hbWUsIHRoaXMgb25seSByZXR1cm5zIHRoZSBmaXJzdCBmaWVsZCdzIHZhbHVlIVxuICAgKiBAcGFyYW0gbmFtZSBOYW1lIG9mIHRoZSBoZWFkZXIgZmllbGRcbiAgICovXG4gIHB1YmxpYyBnZXRIZWFkZXIobmFtZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgICBjb25zdCBpbmRleCA9IHRoaXMuX2luZGV4T2ZIZWFkZXIobmFtZS50b0xvd2VyQ2FzZSgpKTtcbiAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICByZXR1cm4gdGhpcy5oZWFkZXJzW2luZGV4XVsxXTtcbiAgICB9XG4gICAgcmV0dXJuICcnO1xuICB9XG5cbiAgLyoqXG4gICAqIFNldCB0aGUgdmFsdWUgb2YgdGhlIGdpdmVuIGhlYWRlciBmaWVsZC4gQXNzdW1lcyB0aGF0IHRoZXJlIGlzIG9ubHkgb25lIGZpZWxkIHdpdGggdGhlIGdpdmVuIG5hbWUuXG4gICAqIElmIHRoZSBmaWVsZCBkb2VzIG5vdCBleGlzdCwgaXQgYWRkcyBhIG5ldyBmaWVsZCB3aXRoIHRoZSBuYW1lIGFuZCB2YWx1ZS5cbiAgICogQHBhcmFtIG5hbWUgTmFtZSBvZiB0aGUgZmllbGQuXG4gICAqIEBwYXJhbSB2YWx1ZSBOZXcgdmFsdWUuXG4gICAqL1xuICBwdWJsaWMgc2V0SGVhZGVyKG5hbWU6IHN0cmluZywgdmFsdWU6IHN0cmluZyk6IHZvaWQge1xuICAgIGNvbnN0IGluZGV4ID0gdGhpcy5faW5kZXhPZkhlYWRlcihuYW1lLnRvTG93ZXJDYXNlKCkpO1xuICAgIGlmIChpbmRleCAhPT0gLTEpIHtcbiAgICAgIHRoaXMuaGVhZGVyc1tpbmRleF1bMV0gPSB2YWx1ZTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5oZWFkZXJzLnB1c2goW25hbWUsIHZhbHVlXSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgdGhlIGhlYWRlciBmaWVsZCB3aXRoIHRoZSBnaXZlbiBuYW1lLiBBc3N1bWVzIHRoYXQgdGhlcmUgaXMgb25seSBvbmUgZmllbGQgd2l0aCB0aGUgZ2l2ZW4gbmFtZS5cbiAgICogRG9lcyBub3RoaW5nIGlmIGZpZWxkIGRvZXMgbm90IGV4aXN0LlxuICAgKiBAcGFyYW0gbmFtZSBOYW1lIG9mIHRoZSBmaWVsZC5cbiAgICovXG4gIHB1YmxpYyByZW1vdmVIZWFkZXIobmFtZTogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3QgaW5kZXggPSB0aGlzLl9pbmRleE9mSGVhZGVyKG5hbWUudG9Mb3dlckNhc2UoKSk7XG4gICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgdGhpcy5oZWFkZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgYWxsIGhlYWRlciBmaWVsZHMuXG4gICAqL1xuICBwdWJsaWMgY2xlYXJIZWFkZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX2hlYWRlcnMgPSBbXTtcbiAgfVxufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYSBNSVRNLWVkIEhUVFAgcmVzcG9uc2UgZnJvbSBhIHNlcnZlci5cbiAqL1xuZXhwb3J0IGNsYXNzIEludGVyY2VwdGVkSFRUUFJlc3BvbnNlIGV4dGVuZHMgQWJzdHJhY3RIVFRQSGVhZGVycyB7XG4gIC8vIFRoZSBzdGF0dXMgY29kZSBvZiB0aGUgSFRUUCByZXNwb25zZS5cbiAgcHVibGljIHN0YXR1c0NvZGU6IG51bWJlcjtcblxuICBjb25zdHJ1Y3RvcihtZXRhZGF0YTogSFRUUFJlc3BvbnNlTWV0YWRhdGEpIHtcbiAgICBzdXBlcihtZXRhZGF0YS5oZWFkZXJzKTtcbiAgICB0aGlzLnN0YXR1c0NvZGUgPSBtZXRhZGF0YS5zdGF0dXNfY29kZTtcbiAgICAvLyBXZSBkb24ndCBzdXBwb3J0IGNodW5rZWQgdHJhbnNmZXJzLiBUaGUgcHJveHkgYWxyZWFkeSBkZS1jaHVua3MgaXQgZm9yIHVzLlxuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCd0cmFuc2Zlci1lbmNvZGluZycpO1xuICAgIC8vIE1JVE1Qcm94eSBkZWNvZGVzIHRoZSBkYXRhIGZvciB1cy5cbiAgICB0aGlzLnJlbW92ZUhlYWRlcignY29udGVudC1lbmNvZGluZycpO1xuICAgIC8vIENTUCBpcyBiYWQhXG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ2NvbnRlbnQtc2VjdXJpdHktcG9saWN5Jyk7XG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ3gtd2Via2l0LWNzcCcpO1xuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCd4LWNvbnRlbnQtc2VjdXJpdHktcG9saWN5Jyk7XG4gIH1cblxuICBwdWJsaWMgdG9KU09OKCk6IEhUVFBSZXNwb25zZU1ldGFkYXRhIHtcbiAgICByZXR1cm4ge1xuICAgICAgc3RhdHVzX2NvZGU6IHRoaXMuc3RhdHVzQ29kZSxcbiAgICAgIGhlYWRlcnM6IHRoaXMuaGVhZGVyc1xuICAgIH07XG4gIH1cbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIGFuIGludGVyY2VwdGVkIEhUVFAgcmVxdWVzdCBmcm9tIGEgY2xpZW50LlxuICovXG5leHBvcnQgY2xhc3MgSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdCBleHRlbmRzIEFic3RyYWN0SFRUUEhlYWRlcnMge1xuICAvLyBIVFRQIG1ldGhvZCAoR0VUL0RFTEVURS9ldGMpXG4gIHB1YmxpYyBtZXRob2Q6IHN0cmluZztcbiAgLy8gVGhlIFVSTCBhcyBhIHN0cmluZy5cbiAgcHVibGljIHJhd1VybDogc3RyaW5nO1xuICAvLyBUaGUgVVJMIGFzIGEgVVJMIG9iamVjdC5cbiAgcHVibGljIHVybDogVXJsO1xuXG4gIGNvbnN0cnVjdG9yKG1ldGFkYXRhOiBIVFRQUmVxdWVzdE1ldGFkYXRhKSB7XG4gICAgc3VwZXIobWV0YWRhdGEuaGVhZGVycyk7XG4gICAgdGhpcy5tZXRob2QgPSBtZXRhZGF0YS5tZXRob2QudG9Mb3dlckNhc2UoKTtcbiAgICB0aGlzLnJhd1VybCA9IG1ldGFkYXRhLnVybDtcbiAgICB0aGlzLnVybCA9IHBhcnNlVVJMKHRoaXMucmF3VXJsKTtcbiAgfVxufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYW4gaW50ZXJjZXB0ZWQgSFRUUCByZXF1ZXN0L3Jlc3BvbnNlIHBhaXIuXG4gKi9cbmV4cG9ydCBjbGFzcyBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlIHtcbiAgLyoqXG4gICAqIFVucGFjayBmcm9tIGEgQnVmZmVyIHJlY2VpdmVkIGZyb20gTUlUTVByb3h5LlxuICAgKiBAcGFyYW0gYlxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBGcm9tQnVmZmVyKGI6IEJ1ZmZlcik6IEludGVyY2VwdGVkSFRUUE1lc3NhZ2Uge1xuICAgIGNvbnN0IG1ldGFkYXRhU2l6ZSA9IGIucmVhZEludDMyTEUoMCk7XG4gICAgY29uc3QgcmVxdWVzdFNpemUgPSBiLnJlYWRJbnQzMkxFKDQpO1xuICAgIGNvbnN0IHJlc3BvbnNlU2l6ZSA9IGIucmVhZEludDMyTEUoOCk7XG4gICAgY29uc3QgbWV0YWRhdGE6IEhUVFBNZXNzYWdlTWV0YWRhdGEgPSBKU09OLnBhcnNlKGIudG9TdHJpbmcoXCJ1dGY4XCIsIDEyLCAxMiArIG1ldGFkYXRhU2l6ZSkpO1xuICAgIHJldHVybiBuZXcgSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZShcbiAgICAgIG5ldyBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0KG1ldGFkYXRhLnJlcXVlc3QpLFxuICAgICAgbmV3IEludGVyY2VwdGVkSFRUUFJlc3BvbnNlKG1ldGFkYXRhLnJlc3BvbnNlKSxcbiAgICAgIGIuc2xpY2UoMTIgKyBtZXRhZGF0YVNpemUsIDEyICsgbWV0YWRhdGFTaXplICsgcmVxdWVzdFNpemUpLFxuICAgICAgYi5zbGljZSgxMiArIG1ldGFkYXRhU2l6ZSArIHJlcXVlc3RTaXplLCAxMiArIG1ldGFkYXRhU2l6ZSArIHJlcXVlc3RTaXplICsgcmVzcG9uc2VTaXplKVxuICAgICk7XG4gIH1cblxuICBwdWJsaWMgcmVhZG9ubHkgcmVxdWVzdDogSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdDtcbiAgcHVibGljIHJlYWRvbmx5IHJlc3BvbnNlOiBJbnRlcmNlcHRlZEhUVFBSZXNwb25zZTtcbiAgLy8gVGhlIGJvZHkgb2YgdGhlIEhUVFAgcmVxdWVzdC5cbiAgcHVibGljIHJlYWRvbmx5IHJlcXVlc3RCb2R5OiBCdWZmZXI7XG4gIC8vIFRoZSBib2R5IG9mIHRoZSBIVFRQIHJlc3BvbnNlLiBSZWFkLW9ubHk7IGNoYW5nZSB0aGUgcmVzcG9uc2UgYm9keSB2aWEgc2V0UmVzcG9uc2VCb2R5LlxuICBwdWJsaWMgZ2V0IHJlc3BvbnNlQm9keSgpOiBCdWZmZXIge1xuICAgIHJldHVybiB0aGlzLl9yZXNwb25zZUJvZHk7XG4gIH1cbiAgcHJpdmF0ZSBfcmVzcG9uc2VCb2R5OiBCdWZmZXI7XG4gIHByaXZhdGUgY29uc3RydWN0b3IocmVxdWVzdDogSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdCwgcmVzcG9uc2U6IEludGVyY2VwdGVkSFRUUFJlc3BvbnNlLCByZXF1ZXN0Qm9keTogQnVmZmVyLCByZXNwb25zZUJvZHk6IEJ1ZmZlcikge1xuICAgIHRoaXMucmVxdWVzdCA9IHJlcXVlc3Q7XG4gICAgdGhpcy5yZXNwb25zZSA9IHJlc3BvbnNlO1xuICAgIHRoaXMucmVxdWVzdEJvZHkgPSByZXF1ZXN0Qm9keTtcbiAgICB0aGlzLl9yZXNwb25zZUJvZHkgPSByZXNwb25zZUJvZHk7XG4gIH1cblxuICAvKipcbiAgICogQ2hhbmdlcyB0aGUgYm9keSBvZiB0aGUgSFRUUCByZXNwb25zZS4gQXBwcm9wcmlhdGVseSB1cGRhdGVzIGNvbnRlbnQtbGVuZ3RoLlxuICAgKiBAcGFyYW0gYiBUaGUgbmV3IGJvZHkgY29udGVudHMuXG4gICAqL1xuICBwdWJsaWMgc2V0UmVzcG9uc2VCb2R5KGI6IEJ1ZmZlcikge1xuICAgIHRoaXMuX3Jlc3BvbnNlQm9keSA9IGI7XG4gICAgLy8gVXBkYXRlIGNvbnRlbnQtbGVuZ3RoLlxuICAgIHRoaXMucmVzcG9uc2Uuc2V0SGVhZGVyKCdjb250ZW50LWxlbmd0aCcsIGAke2IubGVuZ3RofWApO1xuICAgIC8vIFRPRE86IENvbnRlbnQtZW5jb2Rpbmc/XG4gIH1cblxuICAvKipcbiAgICogUGFjayBpbnRvIGEgYnVmZmVyIGZvciB0cmFuc21pc3Npb24gdG8gTUlUTVByb3h5LlxuICAgKi9cbiAgcHVibGljIHRvQnVmZmVyKCk6IEJ1ZmZlciB7XG4gICAgY29uc3QgbWV0YWRhdGEgPSBCdWZmZXIuZnJvbShKU09OLnN0cmluZ2lmeSh0aGlzLnJlc3BvbnNlKSwgJ3V0ZjgnKTtcbiAgICBjb25zdCBtZXRhZGF0YUxlbmd0aCA9IG1ldGFkYXRhLmxlbmd0aDtcbiAgICBjb25zdCByZXNwb25zZUxlbmd0aCA9IHRoaXMuX3Jlc3BvbnNlQm9keS5sZW5ndGhcbiAgICBjb25zdCBydiA9IEJ1ZmZlci5hbGxvYyg4ICsgbWV0YWRhdGFMZW5ndGggKyByZXNwb25zZUxlbmd0aCk7XG4gICAgcnYud3JpdGVJbnQzMkxFKG1ldGFkYXRhTGVuZ3RoLCAwKTtcbiAgICBydi53cml0ZUludDMyTEUocmVzcG9uc2VMZW5ndGgsIDQpO1xuICAgIG1ldGFkYXRhLmNvcHkocnYsIDgpO1xuICAgIHRoaXMuX3Jlc3BvbnNlQm9keS5jb3B5KHJ2LCA4ICsgbWV0YWRhdGFMZW5ndGgpO1xuICAgIHJldHVybiBydjtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU3Rhc2hlZEl0ZW0ge1xuICBjb25zdHJ1Y3RvcihcbiAgICBwdWJsaWMgcmVhZG9ubHkgcmF3VXJsOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IG1pbWVUeXBlOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IGRhdGE6IEJ1ZmZlcikge31cblxuICBwdWJsaWMgZ2V0IHNob3J0TWltZVR5cGUoKTogc3RyaW5nIHtcbiAgICBsZXQgbWltZSA9IHRoaXMubWltZVR5cGUudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAobWltZS5pbmRleE9mKFwiO1wiKSAhPT0gLTEpIHtcbiAgICAgIG1pbWUgPSBtaW1lLnNsaWNlKDAsIG1pbWUuaW5kZXhPZihcIjtcIikpO1xuICAgIH1cbiAgICByZXR1cm4gbWltZTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgaXNIdG1sKCk6IGJvb2xlYW4ge1xuICAgIHJldHVybiB0aGlzLnNob3J0TWltZVR5cGUgPT09IFwidGV4dC9odG1sXCI7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGlzSmF2YVNjcmlwdCgpOiBib29sZWFuIHtcbiAgICBzd2l0Y2godGhpcy5zaG9ydE1pbWVUeXBlKSB7XG4gICAgICBjYXNlICd0ZXh0L2phdmFzY3JpcHQnOlxuICAgICAgY2FzZSAnYXBwbGljYXRpb24vamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICd0ZXh0L3gtamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICdhcHBsaWNhdGlvbi94LWphdmFzY3JpcHQnOlxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cbn1cblxuZnVuY3Rpb24gZGVmYXVsdFN0YXNoRmlsdGVyKHVybDogc3RyaW5nLCBpdGVtOiBTdGFzaGVkSXRlbSk6IGJvb2xlYW4ge1xuICByZXR1cm4gaXRlbS5pc0phdmFTY3JpcHQgfHwgaXRlbS5pc0h0bWw7XG59XG5cbi8qKlxuICogQ2xhc3MgdGhhdCBsYXVuY2hlcyBNSVRNIHByb3h5IGFuZCB0YWxrcyB0byBpdCB2aWEgV2ViU29ja2V0cy5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgY2xhc3MgTUlUTVByb3h5IHtcbiAgcHJpdmF0ZSBzdGF0aWMgX2FjdGl2ZVByb2Nlc3NlczogQ2hpbGRQcm9jZXNzW10gPSBbXTtcblxuICAvKipcbiAgICogQ3JlYXRlcyBhIG5ldyBNSVRNUHJveHkgaW5zdGFuY2UuXG4gICAqIEBwYXJhbSBjYiBDYWxsZWQgd2l0aCBpbnRlcmNlcHRlZCBIVFRQIHJlcXVlc3RzIC8gcmVzcG9uc2VzLlxuICAgKiBAcGFyYW0gaW50ZXJjZXB0UGF0aHMgTGlzdCBvZiBwYXRocyB0byBjb21wbGV0ZWx5IGludGVyY2VwdCB3aXRob3V0IHNlbmRpbmcgdG8gdGhlIHNlcnZlciAoZS5nLiBbJy9ldmFsJ10pXG4gICAqIEBwYXJhbSBxdWlldCBJZiB0cnVlLCBkbyBub3QgcHJpbnQgZGVidWdnaW5nIG1lc3NhZ2VzIChkZWZhdWx0cyB0byAndHJ1ZScpLlxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBhc3luYyBDcmVhdGUoY2I6IEludGVyY2VwdG9yID0gbm9wSW50ZXJjZXB0b3IsIGludGVyY2VwdFBhdGhzOiBzdHJpbmdbXSA9IFtdLCBxdWlldDogYm9vbGVhbiA9IHRydWUpOiBQcm9taXNlPE1JVE1Qcm94eT4ge1xuICAgIC8vIENvbnN0cnVjdCBXZWJTb2NrZXQgc2VydmVyLCBhbmQgd2FpdCBmb3IgaXQgdG8gYmVnaW4gbGlzdGVuaW5nLlxuICAgIGNvbnN0IHdzcyA9IG5ldyBXZWJTb2NrZXRTZXJ2ZXIoeyBwb3J0OiA4NzY1IH0pO1xuICAgIGNvbnN0IHByb3h5Q29ubmVjdGVkID0gbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgd3NzLm9uY2UoJ2Nvbm5lY3Rpb24nLCAoKSA9PiB7XG4gICAgICAgIHJlc29sdmUoKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuICAgIGNvbnN0IG1wID0gbmV3IE1JVE1Qcm94eShjYik7XG4gICAgLy8gU2V0IHVwIFdTUyBjYWxsYmFja3MgYmVmb3JlIE1JVE1Qcm94eSBjb25uZWN0cy5cbiAgICBtcC5faW5pdGlhbGl6ZVdTUyh3c3MpO1xuICAgIGF3YWl0IG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHdzcy5vbmNlKCdsaXN0ZW5pbmcnLCAoKSA9PiB7XG4gICAgICAgIHdzcy5yZW1vdmVMaXN0ZW5lcignZXJyb3InLCByZWplY3QpO1xuICAgICAgICByZXNvbHZlKCk7XG4gICAgICB9KTtcbiAgICAgIHdzcy5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgfSk7XG5cbiAgICB0cnkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgYXdhaXQgd2FpdEZvclBvcnQoODA4MCwgMSk7XG4gICAgICAgIGlmICghcXVpZXQpIHtcbiAgICAgICAgICBjb25zb2xlLmxvZyhgTUlUTVByb3h5IGFscmVhZHkgcnVubmluZy5gKTtcbiAgICAgICAgfVxuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoIXF1aWV0KSB7XG4gICAgICAgICAgY29uc29sZS5sb2coYE1JVE1Qcm94eSBub3QgcnVubmluZzsgc3RhcnRpbmcgdXAgbWl0bXByb3h5LmApO1xuICAgICAgICB9XG4gICAgICAgIC8vIFN0YXJ0IHVwIE1JVE0gcHJvY2Vzcy5cbiAgICAgICAgLy8gLS1hbnRpY2FjaGUgbWVhbnMgdG8gZGlzYWJsZSBjYWNoaW5nLCB3aGljaCBnZXRzIGluIHRoZSB3YXkgb2YgdHJhbnNwYXJlbnRseSByZXdyaXRpbmcgY29udGVudC5cbiAgICAgICAgY29uc3Qgc2NyaXB0QXJncyA9IGludGVyY2VwdFBhdGhzLmxlbmd0aCA+IDAgPyBbXCItLXNldFwiLCBgaW50ZXJjZXB0PSR7aW50ZXJjZXB0UGF0aHMuam9pbihcIixcIil9YF0gOiBbXTtcbiAgICAgICAgY29uc3Qgb3B0aW9ucyA9IFtcIi0tYW50aWNhY2hlXCIsIFwiLXNcIiwgcmVzb2x2ZShfX2Rpcm5hbWUsIGAuLi9zY3JpcHRzL3Byb3h5LnB5YCldLmNvbmNhdChzY3JpcHRBcmdzKTtcbiAgICAgICAgaWYgKHF1aWV0KSB7XG4gICAgICAgICAgb3B0aW9ucy5wdXNoKCctcScpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IG1pdG1Qcm9jZXNzID0gc3Bhd24oXCJtaXRtZHVtcFwiLCBvcHRpb25zLCB7XG4gICAgICAgICAgc3RkaW86ICdpbmhlcml0J1xuICAgICAgICB9KTtcbiAgICAgICAgY29uc3QgbWl0bVByb3h5RXhpdGVkID0gbmV3IFByb21pc2U8dm9pZD4oKF8sIHJlamVjdCkgPT4ge1xuICAgICAgICAgIG1pdG1Qcm9jZXNzLm9uY2UoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICAgICAgICBtaXRtUHJvY2Vzcy5vbmNlKCdleGl0JywgcmVqZWN0KTtcbiAgICAgICAgfSk7XG4gICAgICAgIGlmIChNSVRNUHJveHkuX2FjdGl2ZVByb2Nlc3Nlcy5wdXNoKG1pdG1Qcm9jZXNzKSA9PT0gMSkge1xuICAgICAgICAgIHByb2Nlc3Mub24oJ1NJR0lOVCcsIE1JVE1Qcm94eS5fY2xlYW51cCk7XG4gICAgICAgICAgcHJvY2Vzcy5vbignZXhpdCcsIE1JVE1Qcm94eS5fY2xlYW51cCk7XG4gICAgICAgIH1cbiAgICAgICAgbXAuX2luaXRpYWxpemVNSVRNUHJveHkobWl0bVByb2Nlc3MpO1xuICAgICAgICAvLyBXYWl0IGZvciBwb3J0IDgwODAgdG8gY29tZSBvbmxpbmUuXG4gICAgICAgIGNvbnN0IHdhaXRpbmdGb3JQb3J0ID0gd2FpdEZvclBvcnQoODA4MCk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgLy8gRmFpbHMgaWYgbWl0bXByb3h5IGV4aXRzIGJlZm9yZSBwb3J0IGJlY29tZXMgYXZhaWxhYmxlLlxuICAgICAgICAgIGF3YWl0IFByb21pc2UucmFjZShbbWl0bVByb3h5RXhpdGVkLCB3YWl0aW5nRm9yUG9ydF0pO1xuICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgaWYgKGUgJiYgdHlwZW9mKGUpID09PSAnb2JqZWN0JyAmJiBlLmNvZGUgPT09IFwiRU5PRU5UXCIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgbWl0bWR1bXAsIHdoaWNoIGlzIGFuIGV4ZWN1dGFibGUgdGhhdCBzaGlwcyB3aXRoIG1pdG1wcm94eSwgaXMgbm90IG9uIHlvdXIgUEFUSC4gUGxlYXNlIGVuc3VyZSB0aGF0IHlvdSBjYW4gcnVuIG1pdG1kdW1wIC0tdmVyc2lvbiBzdWNjZXNzZnVsbHkgZnJvbSB5b3VyIGNvbW1hbmQgbGluZS5gKVxuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYFVuYWJsZSB0byBzdGFydCBtaXRtcHJveHk6ICR7ZX1gKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGF3YWl0IHByb3h5Q29ubmVjdGVkO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGF3YWl0IG5ldyBQcm9taXNlPGFueT4oKHJlc29sdmUpID0+IHdzcy5jbG9zZShyZXNvbHZlKSk7XG4gICAgICB0aHJvdyBlO1xuICAgIH1cblxuICAgIHJldHVybiBtcDtcbiAgfVxuXG4gIHByaXZhdGUgc3RhdGljIF9jbGVhbnVwQ2FsbGVkID0gZmFsc2U7XG4gIHByaXZhdGUgc3RhdGljIF9jbGVhbnVwKCk6IHZvaWQge1xuICAgIGlmIChNSVRNUHJveHkuX2NsZWFudXBDYWxsZWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgTUlUTVByb3h5Ll9jbGVhbnVwQ2FsbGVkID0gdHJ1ZTtcbiAgICBNSVRNUHJveHkuX2FjdGl2ZVByb2Nlc3Nlcy5mb3JFYWNoKChwKSA9PiB7XG4gICAgICBwLmtpbGwoJ1NJR0tJTEwnKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0YXNoRW5hYmxlZDogYm9vbGVhbiA9IGZhbHNlO1xuICAvLyBUb2dnbGUgd2hldGhlciBvciBub3QgbWl0bXByb3h5LW5vZGUgc3Rhc2hlcyBtb2RpZmllZCBzZXJ2ZXIgcmVzcG9uc2VzLlxuICAvLyAqKk5vdCB1c2VkIGZvciBwZXJmb3JtYW5jZSoqLCBidXQgZW5hYmxlcyBOb2RlLmpzIGNvZGUgdG8gZmV0Y2ggcHJldmlvdXMgc2VydmVyIHJlc3BvbnNlcyBmcm9tIHRoZSBwcm94eS5cbiAgcHVibGljIGdldCBzdGFzaEVuYWJsZWQoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMuX3N0YXNoRW5hYmxlZDtcbiAgfVxuICBwdWJsaWMgc2V0IHN0YXNoRW5hYmxlZCh2OiBib29sZWFuKSB7XG4gICAgaWYgKCF2KSB7XG4gICAgICB0aGlzLl9zdGFzaC5jbGVhcigpO1xuICAgIH1cbiAgICB0aGlzLl9zdGFzaEVuYWJsZWQgPSB2O1xuICB9XG4gIHByaXZhdGUgX21pdG1Qcm9jZXNzOiBDaGlsZFByb2Nlc3MgPSBudWxsO1xuICBwcml2YXRlIF9taXRtRXJyb3I6IEVycm9yID0gbnVsbDtcbiAgcHJpdmF0ZSBfd3NzOiBXZWJTb2NrZXRTZXJ2ZXIgPSBudWxsO1xuICBwdWJsaWMgY2I6IEludGVyY2VwdG9yO1xuICBwcml2YXRlIF9zdGFzaCA9IG5ldyBNYXA8c3RyaW5nLCBTdGFzaGVkSXRlbT4oKTtcbiAgcHJpdmF0ZSBfc3Rhc2hGaWx0ZXI6ICh1cmw6IHN0cmluZywgaXRlbTogU3Rhc2hlZEl0ZW0pID0+IGJvb2xlYW4gPSBkZWZhdWx0U3Rhc2hGaWx0ZXI7XG4gIHB1YmxpYyBnZXQgc3Rhc2hGaWx0ZXIoKTogKHVybDogc3RyaW5nLCBpdGVtOiBTdGFzaGVkSXRlbSkgPT4gYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMuX3N0YXNoRmlsdGVyO1xuICB9XG4gIHB1YmxpYyBzZXQgc3Rhc2hGaWx0ZXIodmFsdWU6ICh1cmw6IHN0cmluZywgaXRlbTogU3Rhc2hlZEl0ZW0pID0+IGJvb2xlYW4pIHtcbiAgICBpZiAodHlwZW9mKHZhbHVlKSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgdGhpcy5fc3Rhc2hGaWx0ZXIgPSB2YWx1ZTtcbiAgICB9IGVsc2UgaWYgKHZhbHVlID09PSBudWxsKSB7XG4gICAgICB0aGlzLl9zdGFzaEZpbHRlciA9IGRlZmF1bHRTdGFzaEZpbHRlcjtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBJbnZhbGlkIHN0YXNoIGZpbHRlcjogRXhwZWN0ZWQgYSBmdW5jdGlvbi5gKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGNvbnN0cnVjdG9yKGNiOiBJbnRlcmNlcHRvcikge1xuICAgIHRoaXMuY2IgPSBjYjtcbiAgfVxuXG4gIHByaXZhdGUgX2luaXRpYWxpemVXU1Mod3NzOiBXZWJTb2NrZXRTZXJ2ZXIpOiB2b2lkIHtcbiAgICB0aGlzLl93c3MgPSB3c3M7XG4gICAgdGhpcy5fd3NzLm9uKCdjb25uZWN0aW9uJywgKHdzKSA9PiB7XG4gICAgICB3cy5vbignbWVzc2FnZScsIGFzeW5jIChtZXNzYWdlOiBCdWZmZXIpID0+IHtcbiAgICAgICAgY29uc3Qgb3JpZ2luYWwgPSBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlLkZyb21CdWZmZXIobWVzc2FnZSk7XG4gICAgICAgIGNvbnN0IHJ2ID0gdGhpcy5jYihvcmlnaW5hbCk7XG4gICAgICAgIGlmIChydiAmJiB0eXBlb2YocnYpID09PSAnb2JqZWN0JyAmJiBydi50aGVuKSB7XG4gICAgICAgICAgYXdhaXQgcnY7XG4gICAgICAgIH1cbiAgICAgICAgLy8gUmVtb3ZlIHRyYW5zZmVyLWVuY29kaW5nLiBXZSBkb24ndCBzdXBwb3J0IGNodW5rZWQuXG4gICAgICAgIGlmICh0aGlzLl9zdGFzaEVuYWJsZWQpIHtcbiAgICAgICAgICBjb25zdCBpdGVtID0gbmV3IFN0YXNoZWRJdGVtKG9yaWdpbmFsLnJlcXVlc3QucmF3VXJsLCBvcmlnaW5hbC5yZXNwb25zZS5nZXRIZWFkZXIoJ2NvbnRlbnQtdHlwZScpLCBvcmlnaW5hbC5yZXNwb25zZUJvZHkpO1xuICAgICAgICAgIGlmICh0aGlzLl9zdGFzaEZpbHRlcihvcmlnaW5hbC5yZXF1ZXN0LnJhd1VybCwgaXRlbSkpIHtcbiAgICAgICAgICAgIHRoaXMuX3N0YXNoLnNldChvcmlnaW5hbC5yZXF1ZXN0LnJhd1VybCwgaXRlbSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHdzLnNlbmQob3JpZ2luYWwudG9CdWZmZXIoKSk7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX2luaXRpYWxpemVNSVRNUHJveHkobWl0bVByb3h5OiBDaGlsZFByb2Nlc3MpOiB2b2lkIHtcbiAgICB0aGlzLl9taXRtUHJvY2VzcyA9IG1pdG1Qcm94eTtcbiAgICB0aGlzLl9taXRtUHJvY2Vzcy5vbignZXhpdCcsIChjb2RlLCBzaWduYWwpID0+IHtcbiAgICAgIGNvbnN0IGluZGV4ID0gTUlUTVByb3h5Ll9hY3RpdmVQcm9jZXNzZXMuaW5kZXhPZih0aGlzLl9taXRtUHJvY2Vzcyk7XG4gICAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICAgIE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLnNwbGljZShpbmRleCwgMSk7XG4gICAgICB9XG4gICAgICBpZiAoY29kZSAhPT0gbnVsbCkge1xuICAgICAgICBpZiAoY29kZSAhPT0gMCkge1xuICAgICAgICAgIHRoaXMuX21pdG1FcnJvciA9IG5ldyBFcnJvcihgUHJvY2VzcyBleGl0ZWQgd2l0aCBjb2RlICR7Y29kZX0uYCk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuX21pdG1FcnJvciA9IG5ldyBFcnJvcihgUHJvY2VzcyBleGl0ZWQgZHVlIHRvIHNpZ25hbCAke3NpZ25hbH0uYCk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3Mub24oJ2Vycm9yJywgKGVycikgPT4ge1xuICAgICAgdGhpcy5fbWl0bUVycm9yID0gZXJyO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHJpZXZlcyB0aGUgZ2l2ZW4gVVJMIGZyb20gdGhlIHN0YXNoLlxuICAgKiBAcGFyYW0gdXJsXG4gICAqL1xuICBwdWJsaWMgZ2V0RnJvbVN0YXNoKHVybDogc3RyaW5nKTogU3Rhc2hlZEl0ZW0ge1xuICAgIHJldHVybiB0aGlzLl9zdGFzaC5nZXQodXJsKTtcbiAgfVxuXG4gIHB1YmxpYyBmb3JFYWNoU3Rhc2hJdGVtKGNiOiAodmFsdWU6IFN0YXNoZWRJdGVtLCB1cmw6IHN0cmluZykgPT4gdm9pZCk6IHZvaWQge1xuICAgIHRoaXMuX3N0YXNoLmZvckVhY2goY2IpO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlcXVlc3RzIHRoZSBnaXZlbiBVUkwgZnJvbSB0aGUgcHJveHkuXG4gICAqL1xuICBwdWJsaWMgYXN5bmMgcHJveHlHZXQodXJsU3RyaW5nOiBzdHJpbmcpOiBQcm9taXNlPEhUVFBSZXNwb25zZT4ge1xuICAgIGNvbnN0IHVybCA9IHBhcnNlVVJMKHVybFN0cmluZyk7XG4gICAgY29uc3QgZ2V0ID0gdXJsLnByb3RvY29sID09PSBcImh0dHA6XCIgPyBodHRwR2V0IDogaHR0cHNHZXQ7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEhUVFBSZXNwb25zZT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgY29uc3QgcmVxID0gZ2V0KHtcbiAgICAgICAgdXJsOiB1cmxTdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICBob3N0OiB1cmwuaG9zdFxuICAgICAgICB9LFxuICAgICAgICBob3N0OiAnbG9jYWxob3N0JyxcbiAgICAgICAgcG9ydDogODA4MCxcbiAgICAgICAgcGF0aDogdXJsU3RyaW5nXG4gICAgICB9LCAocmVzKSA9PiB7XG4gICAgICAgIGNvbnN0IGRhdGEgPSBuZXcgQXJyYXk8QnVmZmVyPigpO1xuICAgICAgICByZXMub24oJ2RhdGEnLCAoY2h1bms6IEJ1ZmZlcikgPT4ge1xuICAgICAgICAgIGRhdGEucHVzaChjaHVuayk7XG4gICAgICAgIH0pO1xuICAgICAgICByZXMub24oJ2VuZCcsICgpID0+IHtcbiAgICAgICAgICBjb25zdCBkID0gQnVmZmVyLmNvbmNhdChkYXRhKTtcbiAgICAgICAgICByZXNvbHZlKHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IHJlcy5zdGF0dXNDb2RlLFxuICAgICAgICAgICAgaGVhZGVyczogcmVzLmhlYWRlcnMsXG4gICAgICAgICAgICBib2R5OiBkXG4gICAgICAgICAgfSBhcyBIVFRQUmVzcG9uc2UpO1xuICAgICAgICB9KTtcbiAgICAgICAgcmVzLm9uY2UoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICAgIH0pO1xuICAgICAgcmVxLm9uY2UoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICB9KTtcbiAgfVxuXG4gIHB1YmxpYyBhc3luYyBzaHV0ZG93bigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgY29uc3QgY2xvc2VXU1MgPSAoKSA9PiB7XG4gICAgICAgIHRoaXMuX3dzcy5jbG9zZSgoZXJyKSA9PiB7XG4gICAgICAgICAgaWYgKGVycikge1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfTtcblxuICAgICAgaWYgKHRoaXMuX21pdG1Qcm9jZXNzICYmICF0aGlzLl9taXRtUHJvY2Vzcy5raWxsZWQpIHtcbiAgICAgICAgdGhpcy5fbWl0bVByb2Nlc3Mub25jZSgnZXhpdCcsIChjb2RlLCBzaWduYWwpID0+IHtcbiAgICAgICAgICBjbG9zZVdTUygpO1xuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5fbWl0bVByb2Nlc3Mua2lsbCgnU0lHVEVSTScpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY2xvc2VXU1MoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufVxuIl19