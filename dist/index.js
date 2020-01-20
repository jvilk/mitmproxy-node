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
     * Changes the status code of the HTTP response.
     * @param code The new status code.
     */
    setStatusCode(code) {
        this.response.statusCode = code;
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
    constructor(cb, onlyInterceptTextFiles) {
        this._stashEnabled = false;
        this._mitmProcess = null;
        this._mitmError = null;
        this._wss = null;
        this._stash = new Map();
        this._stashFilter = defaultStashFilter;
        this.cb = cb;
        this.onlyInterceptTextFiles = onlyInterceptTextFiles;
    }
    /**
     * Creates a new MITMProxy instance.
     * @param cb Called with intercepted HTTP requests / responses.
     * @param interceptPaths List of paths to completely intercept without sending to the server (e.g. ['/eval'])
     * @param quiet If true, do not print debugging messages (defaults to 'true').
     * @param onlyInterceptTextFiles If true, only intercept text files (JavaScript/HTML/CSS/etc, and ignore media files).
     */
    static Create(cb = nopInterceptor, interceptPaths = [], quiet = true, onlyInterceptTextFiles = false, ignoreHosts = null) {
        return __awaiter(this, void 0, void 0, function* () {
            // Construct WebSocket server, and wait for it to begin listening.
            const wss = new ws_1.Server({ port: 8765 });
            const proxyConnected = new Promise((resolve, reject) => {
                wss.once('connection', () => {
                    resolve();
                });
            });
            const mp = new MITMProxy(cb, onlyInterceptTextFiles);
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
                    scriptArgs.push("--set", `onlyInterceptTextFiles=${onlyInterceptTextFiles}`);
                    if (ignoreHosts) {
                        scriptArgs.push(`--ignore-hosts`, ignoreHosts);
                    }
                    const options = ["--anticache", "-s", path_1.resolve(__dirname, `../scripts/proxy.py`)].concat(scriptArgs);
                    if (quiet) {
                        options.push('-q');
                    }
                    // allow self-signed SSL certificates
                    options.push("--ssl-insecure");
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
            ws.on('error', (e) => {
                if (e.code !== "ECONNRESET") {
                    console.log(`WebSocket error: ${e}`);
                }
            });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQUFBLDJCQUE2QztBQUM3QyxpREFBa0Q7QUFDbEQsK0JBQTZCO0FBQzdCLDZCQUEyQztBQUMzQywrQkFBb0M7QUFDcEMsaUNBQXNDO0FBQ3RDLDZCQUE2QztBQUU3Qzs7Ozs7R0FLRztBQUNILHFCQUFxQixJQUFZLEVBQUUsVUFBa0IsRUFBRSxFQUFFLFdBQW1CLEdBQUc7SUFDN0UsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQzNDLElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDO1FBQy9CLElBQUksYUFBYSxHQUFHLFFBQVEsQ0FBQztRQUM3QixJQUFJLEtBQUssR0FBaUIsSUFBSSxDQUFDO1FBQy9CLElBQUksTUFBTSxHQUFXLElBQUksQ0FBQztRQUUxQjtZQUNFLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUNwQixLQUFLLEdBQUcsSUFBSSxDQUFDO1lBQ2IsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDO2dCQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUM3QixNQUFNLEdBQUcsSUFBSSxDQUFDO1FBQ2hCLENBQUM7UUFFRDtZQUNFLFlBQVksRUFBRSxDQUFDO1FBQ2pCLENBQUM7UUFFRDtZQUNFLDBCQUEwQixFQUFFLENBQUM7WUFFN0IsRUFBRSxDQUFDLENBQUMsRUFBRSxnQkFBZ0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMzQixNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDO1lBQ3RDLENBQUM7WUFFRCxNQUFNLEdBQUcsc0JBQWdCLENBQUMsSUFBSSxFQUFFLFdBQVcsRUFBRTtnQkFDM0MsMEJBQTBCLEVBQUUsQ0FBQztnQkFDN0IsRUFBRSxDQUFDLENBQUMsZ0JBQWdCLElB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QUFBO0lBRVksUUFBUTs7WUFDbkIsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO2dCQUMzQyxNQUFNLFFBQVEsR0FBRyxHQUFHLEVBQUU7b0JBQ3BCLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUU7d0JBQ3RCLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7NEJBQ1IsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO3dCQUNkLENBQUM7d0JBQUMsSUFBSSxDQUFDLENBQUM7NEJBQ04sT0FBTyxFQUFFLENBQUM7d0JBQ1osQ0FBQztvQkFDSCxDQUFDLENBQUMsQ0FBQztnQkFDTCxDQUFDLENBQUM7Z0JBRUYsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFlBQVksSUFBSSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztvQkFDbkQsSUFBSSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sRUFBRSxFQUFFO3dCQUM5QyxRQUFRLEVBQUUsQ0FBQztvQkFDYixDQUFDLENBQUMsQ0FBQztvQkFDSCxJQUFJLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQztnQkFDcEMsQ0FBQztnQkFBQyxJQUFJLENBQUMsQ0FBQztvQkFDTixRQUFRLEVBQUUsQ0FBQztnQkFDYixDQUFDO1lBQ0gsQ0FBQyxDQUFDLENBQUM7UUFDTCxDQUFDO0tBQUE7O0FBelBjLDBCQUFnQixHQUFtQixFQUFFLENBQUM7QUF3RnRDLHdCQUFjLEdBQUcsS0FBSyxDQUFDO0FBekZ4Qyw0QkEyUEMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1NlcnZlciBhcyBXZWJTb2NrZXRTZXJ2ZXJ9IGZyb20gJ3dzJztcbmltcG9ydCB7c3Bhd24sIENoaWxkUHJvY2Vzc30gZnJvbSAnY2hpbGRfcHJvY2Vzcyc7XG5pbXBvcnQge3Jlc29sdmV9IGZyb20gJ3BhdGgnO1xuaW1wb3J0IHtwYXJzZSBhcyBwYXJzZVVSTCwgVXJsfSBmcm9tICd1cmwnO1xuaW1wb3J0IHtnZXQgYXMgaHR0cEdldH0gZnJvbSAnaHR0cCc7XG5pbXBvcnQge2dldCBhcyBodHRwc0dldH0gZnJvbSAnaHR0cHMnO1xuaW1wb3J0IHtjcmVhdGVDb25uZWN0aW9uLCBTb2NrZXR9IGZyb20gJ25ldCc7XG5cbi8qKlxuICogV2FpdCBmb3IgdGhlIHNwZWNpZmllZCBwb3J0IHRvIG9wZW4uXG4gKiBAcGFyYW0gcG9ydCBUaGUgcG9ydCB0byB3YXRjaCBmb3IuXG4gKiBAcGFyYW0gcmV0cmllcyBUaGUgbnVtYmVyIG9mIHRpbWVzIHRvIHJldHJ5IGJlZm9yZSBnaXZpbmcgdXAuIERlZmF1bHRzIHRvIDEwLlxuICogQHBhcmFtIGludGVydmFsIFRoZSBpbnRlcnZhbCBiZXR3ZWVuIHJldHJpZXMsIGluIG1pbGxpc2Vjb25kcy4gRGVmYXVsdHMgdG8gNTAwLlxuICovXG5mdW5jdGlvbiB3YWl0Rm9yUG9ydChwb3J0OiBudW1iZXIsIHJldHJpZXM6IG51bWJlciA9IDEwLCBpbnRlcnZhbDogbnVtYmVyID0gNTAwKTogUHJvbWlzZTx2b2lkPiB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgbGV0IHJldHJpZXNSZW1haW5pbmcgPSByZXRyaWVzO1xuICAgIGxldCByZXRyeUludGVydmFsID0gaW50ZXJ2YWw7XG4gICAgbGV0IHRpbWVyOiBOb2RlSlMuVGltZXIgPSBudWxsO1xuICAgIGxldCBzb2NrZXQ6IFNvY2tldCA9IG51bGw7XG5cbiAgICBmdW5jdGlvbiBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aW1lcik7XG4gICAgICB0aW1lciA9IG51bGw7XG4gICAgICBpZiAoc29ja2V0KSBzb2NrZXQuZGVzdHJveSgpO1xuICAgICAgc29ja2V0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZXRyeSgpIHtcbiAgICAgIHRyeVRvQ29ubmVjdCgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyeVRvQ29ubmVjdCgpIHtcbiAgICAgIGNsZWFyVGltZXJBbmREZXN0cm95U29ja2V0KCk7XG5cbiAgICAgIGlmICgtLXJldHJpZXNSZW1haW5pbmcgPCAwKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ291dCBvZiByZXRyaWVzJykpO1xuICAgICAgfVxuXG4gICAgICBzb2NrZXQgPSBjcmVhdGVDb25uZWN0aW9uKHBvcnQsIFwibG9jYWxob3N0XCIsIGZ1bmN0aW9uKCkge1xuICAgICAgICBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpO1xuICAgICAgICBpZiAocmV0cmllc1JlbWFpbmluZyA+PSAwKSByZXNvbHZlKCk7XG4gICAgICB9KTtcblxuICAgICAgdGltZXIgPSBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgeyByZXRyeSgpOyB9LCByZXRyeUludGVydmFsKTtcblxuICAgICAgc29ja2V0Lm9uKCdlcnJvcicsIGZ1bmN0aW9uKGVycikge1xuICAgICAgICBjbGVhclRpbWVyQW5kRGVzdHJveVNvY2tldCgpO1xuICAgICAgICBzZXRUaW1lb3V0KHJldHJ5LCByZXRyeUludGVydmFsKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHRyeVRvQ29ubmVjdCgpO1xuICB9KTtcbn1cblxuLyoqXG4gKiBGdW5jdGlvbiB0aGF0IGludGVyY2VwdHMgYW5kIHJld3JpdGVzIEhUVFAgcmVzcG9uc2VzLlxuICovXG5leHBvcnQgdHlwZSBJbnRlcmNlcHRvciA9IChtOiBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlKSA9PiB2b2lkIHwgUHJvbWlzZTx2b2lkPjtcblxuLyoqXG4gKiBBbiBpbnRlcmNlcHRvciB0aGF0IGRvZXMgbm90aGluZy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIG5vcEludGVyY2VwdG9yKG06IEludGVyY2VwdGVkSFRUUE1lc3NhZ2UpOiB2b2lkIHt9XG5cbi8qKlxuICogVGhlIGNvcmUgSFRUUCByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBIVFRQUmVzcG9uc2Uge1xuICBzdGF0dXNDb2RlOiBudW1iZXIsXG4gIGhlYWRlcnM6IHtbbmFtZTogc3RyaW5nXTogc3RyaW5nfTtcbiAgYm9keTogQnVmZmVyO1xufVxuXG4vKipcbiAqIE1ldGFkYXRhIGFzc29jaWF0ZWQgd2l0aCBhIHJlcXVlc3QvcmVzcG9uc2UgcGFpci5cbiAqL1xuaW50ZXJmYWNlIEhUVFBNZXNzYWdlTWV0YWRhdGEge1xuICByZXF1ZXN0OiBIVFRQUmVxdWVzdE1ldGFkYXRhO1xuICByZXNwb25zZTogSFRUUFJlc3BvbnNlTWV0YWRhdGE7XG59XG5cbi8qKlxuICogTWV0YWRhdGEgYXNzb2NpYXRlZCB3aXRoIGFuIEhUVFAgcmVxdWVzdC5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBIVFRQUmVxdWVzdE1ldGFkYXRhIHtcbiAgLy8gR0VULCBERUxFVEUsIFBPU1QsICBldGMuXG4gIG1ldGhvZDogc3RyaW5nO1xuICAvLyBUYXJnZXQgVVJMIGZvciB0aGUgcmVxdWVzdC5cbiAgdXJsOiBzdHJpbmc7XG4gIC8vIFRoZSBzZXQgb2YgaGVhZGVycyBmcm9tIHRoZSByZXF1ZXN0LCBhcyBrZXktdmFsdWUgcGFpcnMuXG4gIC8vIFNpbmNlIGhlYWRlciBmaWVsZHMgbWF5IGJlIHJlcGVhdGVkLCB0aGlzIGFycmF5IG1heSBjb250YWluIG11bHRpcGxlIGVudHJpZXMgZm9yIHRoZSBzYW1lIGtleS5cbiAgaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdO1xufVxuXG4vKipcbiAqIE1ldGFkYXRhIGFzc29jaWF0ZWQgd2l0aCBhbiBIVFRQIHJlc3BvbnNlLlxuICovXG5leHBvcnQgaW50ZXJmYWNlIEhUVFBSZXNwb25zZU1ldGFkYXRhIHtcbiAgLy8gVGhlIG51bWVyaWNhbCBzdGF0dXMgY29kZS5cbiAgc3RhdHVzX2NvZGU6IG51bWJlcjtcbiAgLy8gVGhlIHNldCBvZiBoZWFkZXJzIGZyb20gdGhlIHJlc3BvbnNlLCBhcyBrZXktdmFsdWUgcGFpcnMuXG4gIC8vIFNpbmNlIGhlYWRlciBmaWVsZHMgbWF5IGJlIHJlcGVhdGVkLCB0aGlzIGFycmF5IG1heSBjb250YWluIG11bHRpcGxlIGVudHJpZXMgZm9yIHRoZSBzYW1lIGtleS5cbiAgaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdO1xufVxuXG4vKipcbiAqIEFic3RyYWN0IGNsYXNzIHRoYXQgcmVwcmVzZW50cyBIVFRQIGhlYWRlcnMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBBYnN0cmFjdEhUVFBIZWFkZXJzIHtcbiAgcHJpdmF0ZSBfaGVhZGVyczogW3N0cmluZywgc3RyaW5nXVtdO1xuICAvLyBUaGUgcmF3IGhlYWRlcnMsIGFzIGEgc2VxdWVuY2Ugb2Yga2V5L3ZhbHVlIHBhaXJzLlxuICAvLyBTaW5jZSBoZWFkZXIgZmllbGRzIG1heSBiZSByZXBlYXRlZCwgdGhpcyBhcnJheSBtYXkgY29udGFpbiBtdWx0aXBsZSBlbnRyaWVzIGZvciB0aGUgc2FtZSBrZXkuXG4gIHB1YmxpYyBnZXQgaGVhZGVycygpOiBbc3RyaW5nLCBzdHJpbmddW10ge1xuICAgIHJldHVybiB0aGlzLl9oZWFkZXJzO1xuICB9XG4gIGNvbnN0cnVjdG9yKGhlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXSkge1xuICAgIHRoaXMuX2hlYWRlcnMgPSBoZWFkZXJzO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5kZXhPZkhlYWRlcihuYW1lOiBzdHJpbmcpOiBudW1iZXIge1xuICAgIGNvbnN0IGhlYWRlcnMgPSB0aGlzLmhlYWRlcnM7XG4gICAgY29uc3QgbGVuID0gaGVhZGVycy5sZW5ndGg7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsZW47IGkrKykge1xuICAgICAgaWYgKGhlYWRlcnNbaV1bMF0udG9Mb3dlckNhc2UoKSA9PT0gbmFtZSkge1xuICAgICAgICByZXR1cm4gaTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIC0xO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgdmFsdWUgb2YgdGhlIGdpdmVuIGhlYWRlciBmaWVsZC5cbiAgICogSWYgdGhlcmUgYXJlIG11bHRpcGxlIGZpZWxkcyB3aXRoIHRoYXQgbmFtZSwgdGhpcyBvbmx5IHJldHVybnMgdGhlIGZpcnN0IGZpZWxkJ3MgdmFsdWUhXG4gICAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGhlYWRlciBmaWVsZFxuICAgKi9cbiAgcHVibGljIGdldEhlYWRlcihuYW1lOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIGNvbnN0IGluZGV4ID0gdGhpcy5faW5kZXhPZkhlYWRlcihuYW1lLnRvTG93ZXJDYXNlKCkpO1xuICAgIGlmIChpbmRleCAhPT0gLTEpIHtcbiAgICAgIHJldHVybiB0aGlzLmhlYWRlcnNbaW5kZXhdWzFdO1xuICAgIH1cbiAgICByZXR1cm4gJyc7XG4gIH1cblxuICAvKipcbiAgICogU2V0IHRoZSB2YWx1ZSBvZiB0aGUgZ2l2ZW4gaGVhZGVyIGZpZWxkLiBBc3N1bWVzIHRoYXQgdGhlcmUgaXMgb25seSBvbmUgZmllbGQgd2l0aCB0aGUgZ2l2ZW4gbmFtZS5cbiAgICogSWYgdGhlIGZpZWxkIGRvZXMgbm90IGV4aXN0LCBpdCBhZGRzIGEgbmV3IGZpZWxkIHdpdGggdGhlIG5hbWUgYW5kIHZhbHVlLlxuICAgKiBAcGFyYW0gbmFtZSBOYW1lIG9mIHRoZSBmaWVsZC5cbiAgICogQHBhcmFtIHZhbHVlIE5ldyB2YWx1ZS5cbiAgICovXG4gIHB1YmxpYyBzZXRIZWFkZXIobmFtZTogc3RyaW5nLCB2YWx1ZTogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3QgaW5kZXggPSB0aGlzLl9pbmRleE9mSGVhZGVyKG5hbWUudG9Mb3dlckNhc2UoKSk7XG4gICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgdGhpcy5oZWFkZXJzW2luZGV4XVsxXSA9IHZhbHVlO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmhlYWRlcnMucHVzaChbbmFtZSwgdmFsdWVdKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlcyB0aGUgaGVhZGVyIGZpZWxkIHdpdGggdGhlIGdpdmVuIG5hbWUuIEFzc3VtZXMgdGhhdCB0aGVyZSBpcyBvbmx5IG9uZSBmaWVsZCB3aXRoIHRoZSBnaXZlbiBuYW1lLlxuICAgKiBEb2VzIG5vdGhpbmcgaWYgZmllbGQgZG9lcyBub3QgZXhpc3QuXG4gICAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGZpZWxkLlxuICAgKi9cbiAgcHVibGljIHJlbW92ZUhlYWRlcihuYW1lOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBjb25zdCBpbmRleCA9IHRoaXMuX2luZGV4T2ZIZWFkZXIobmFtZS50b0xvd2VyQ2FzZSgpKTtcbiAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICB0aGlzLmhlYWRlcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlcyBhbGwgaGVhZGVyIGZpZWxkcy5cbiAgICovXG4gIHB1YmxpYyBjbGVhckhlYWRlcnMoKTogdm9pZCB7XG4gICAgdGhpcy5faGVhZGVycyA9IFtdO1xuICB9XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyBhIE1JVE0tZWQgSFRUUCByZXNwb25zZSBmcm9tIGEgc2VydmVyLlxuICovXG5leHBvcnQgY2xhc3MgSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2UgZXh0ZW5kcyBBYnN0cmFjdEhUVFBIZWFkZXJzIHtcbiAgLy8gVGhlIHN0YXR1cyBjb2RlIG9mIHRoZSBIVFRQIHJlc3BvbnNlLlxuICBwdWJsaWMgc3RhdHVzQ29kZTogbnVtYmVyO1xuXG4gIGNvbnN0cnVjdG9yKG1ldGFkYXRhOiBIVFRQUmVzcG9uc2VNZXRhZGF0YSkge1xuICAgIHN1cGVyKG1ldGFkYXRhLmhlYWRlcnMpO1xuICAgIHRoaXMuc3RhdHVzQ29kZSA9IG1ldGFkYXRhLnN0YXR1c19jb2RlO1xuICAgIC8vIFdlIGRvbid0IHN1cHBvcnQgY2h1bmtlZCB0cmFuc2ZlcnMuIFRoZSBwcm94eSBhbHJlYWR5IGRlLWNodW5rcyBpdCBmb3IgdXMuXG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ3RyYW5zZmVyLWVuY29kaW5nJyk7XG4gICAgLy8gTUlUTVByb3h5IGRlY29kZXMgdGhlIGRhdGEgZm9yIHVzLlxuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCdjb250ZW50LWVuY29kaW5nJyk7XG4gICAgLy8gQ1NQIGlzIGJhZCFcbiAgICB0aGlzLnJlbW92ZUhlYWRlcignY29udGVudC1zZWN1cml0eS1wb2xpY3knKTtcbiAgICB0aGlzLnJlbW92ZUhlYWRlcigneC13ZWJraXQtY3NwJyk7XG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ3gtY29udGVudC1zZWN1cml0eS1wb2xpY3knKTtcbiAgfVxuXG4gIHB1YmxpYyB0b0pTT04oKTogSFRUUFJlc3BvbnNlTWV0YWRhdGEge1xuICAgIHJldHVybiB7XG4gICAgICBzdGF0dXNfY29kZTogdGhpcy5zdGF0dXNDb2RlLFxuICAgICAgaGVhZGVyczogdGhpcy5oZWFkZXJzXG4gICAgfTtcbiAgfVxufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYW4gaW50ZXJjZXB0ZWQgSFRUUCByZXF1ZXN0IGZyb20gYSBjbGllbnQuXG4gKi9cbmV4cG9ydCBjbGFzcyBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0IGV4dGVuZHMgQWJzdHJhY3RIVFRQSGVhZGVycyB7XG4gIC8vIEhUVFAgbWV0aG9kIChHRVQvREVMRVRFL2V0YylcbiAgcHVibGljIG1ldGhvZDogc3RyaW5nO1xuICAvLyBUaGUgVVJMIGFzIGEgc3RyaW5nLlxuICBwdWJsaWMgcmF3VXJsOiBzdHJpbmc7XG4gIC8vIFRoZSBVUkwgYXMgYSBVUkwgb2JqZWN0LlxuICBwdWJsaWMgdXJsOiBVcmw7XG5cbiAgY29uc3RydWN0b3IobWV0YWRhdGE6IEhUVFBSZXF1ZXN0TWV0YWRhdGEpIHtcbiAgICBzdXBlcihtZXRhZGF0YS5oZWFkZXJzKTtcbiAgICB0aGlzLm1ldGhvZCA9IG1ldGFkYXRhLm1ldGhvZC50b0xvd2VyQ2FzZSgpO1xuICAgIHRoaXMucmF3VXJsID0gbWV0YWRhdGEudXJsO1xuICAgIHRoaXMudXJsID0gcGFyc2VVUkwodGhpcy5yYXdVcmwpO1xuICB9XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyBhbiBpbnRlcmNlcHRlZCBIVFRQIHJlcXVlc3QvcmVzcG9uc2UgcGFpci5cbiAqL1xuZXhwb3J0IGNsYXNzIEludGVyY2VwdGVkSFRUUE1lc3NhZ2Uge1xuICAvKipcbiAgICogVW5wYWNrIGZyb20gYSBCdWZmZXIgcmVjZWl2ZWQgZnJvbSBNSVRNUHJveHkuXG4gICAqIEBwYXJhbSBiXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIEZyb21CdWZmZXIoYjogQnVmZmVyKTogSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZSB7XG4gICAgY29uc3QgbWV0YWRhdGFTaXplID0gYi5yZWFkSW50MzJMRSgwKTtcbiAgICBjb25zdCByZXF1ZXN0U2l6ZSA9IGIucmVhZEludDMyTEUoNCk7XG4gICAgY29uc3QgcmVzcG9uc2VTaXplID0gYi5yZWFkSW50MzJMRSg4KTtcbiAgICBjb25zdCBtZXRhZGF0YTogSFRUUE1lc3NhZ2VNZXRhZGF0YSA9IEpTT04ucGFyc2UoYi50b1N0cmluZyhcInV0ZjhcIiwgMTIsIDEyICsgbWV0YWRhdGFTaXplKSk7XG4gICAgcmV0dXJuIG5ldyBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlKFxuICAgICAgbmV3IEludGVyY2VwdGVkSFRUUFJlcXVlc3QobWV0YWRhdGEucmVxdWVzdCksXG4gICAgICBuZXcgSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2UobWV0YWRhdGEucmVzcG9uc2UpLFxuICAgICAgYi5zbGljZSgxMiArIG1ldGFkYXRhU2l6ZSwgMTIgKyBtZXRhZGF0YVNpemUgKyByZXF1ZXN0U2l6ZSksXG4gICAgICBiLnNsaWNlKDEyICsgbWV0YWRhdGFTaXplICsgcmVxdWVzdFNpemUsIDEyICsgbWV0YWRhdGFTaXplICsgcmVxdWVzdFNpemUgKyByZXNwb25zZVNpemUpXG4gICAgKTtcbiAgfVxuXG4gIHB1YmxpYyByZWFkb25seSByZXF1ZXN0OiBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0O1xuICBwdWJsaWMgcmVhZG9ubHkgcmVzcG9uc2U6IEludGVyY2VwdGVkSFRUUFJlc3BvbnNlO1xuICAvLyBUaGUgYm9keSBvZiB0aGUgSFRUUCByZXF1ZXN0LlxuICBwdWJsaWMgcmVhZG9ubHkgcmVxdWVzdEJvZHk6IEJ1ZmZlcjtcbiAgLy8gVGhlIGJvZHkgb2YgdGhlIEhUVFAgcmVzcG9uc2UuIFJlYWQtb25seTsgY2hhbmdlIHRoZSByZXNwb25zZSBib2R5IHZpYSBzZXRSZXNwb25zZUJvZHkuXG4gIHB1YmxpYyBnZXQgcmVzcG9uc2VCb2R5KCk6IEJ1ZmZlciB7XG4gICAgcmV0dXJuIHRoaXMuX3Jlc3BvbnNlQm9keTtcbiAgfVxuICBwcml2YXRlIF9yZXNwb25zZUJvZHk6IEJ1ZmZlcjtcbiAgcHJpdmF0ZSBjb25zdHJ1Y3RvcihyZXF1ZXN0OiBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0LCByZXNwb25zZTogSW50ZXJjZXB0ZWRIVFRQUmVzcG9uc2UsIHJlcXVlc3RCb2R5OiBCdWZmZXIsIHJlc3BvbnNlQm9keTogQnVmZmVyKSB7XG4gICAgdGhpcy5yZXF1ZXN0ID0gcmVxdWVzdDtcbiAgICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gICAgdGhpcy5yZXF1ZXN0Qm9keSA9IHJlcXVlc3RCb2R5O1xuICAgIHRoaXMuX3Jlc3BvbnNlQm9keSA9IHJlc3BvbnNlQm9keTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGFuZ2VzIHRoZSBib2R5IG9mIHRoZSBIVFRQIHJlc3BvbnNlLiBBcHByb3ByaWF0ZWx5IHVwZGF0ZXMgY29udGVudC1sZW5ndGguXG4gICAqIEBwYXJhbSBiIFRoZSBuZXcgYm9keSBjb250ZW50cy5cbiAgICovXG4gIHB1YmxpYyBzZXRSZXNwb25zZUJvZHkoYjogQnVmZmVyKSB7XG4gICAgdGhpcy5fcmVzcG9uc2VCb2R5ID0gYjtcbiAgICAvLyBVcGRhdGUgY29udGVudC1sZW5ndGguXG4gICAgdGhpcy5yZXNwb25zZS5zZXRIZWFkZXIoJ2NvbnRlbnQtbGVuZ3RoJywgYCR7Yi5sZW5ndGh9YCk7XG4gICAgLy8gVE9ETzogQ29udGVudC1lbmNvZGluZz9cbiAgfVxuICBcbiAgLyoqXG4gICAqIENoYW5nZXMgdGhlIHN0YXR1cyBjb2RlIG9mIHRoZSBIVFRQIHJlc3BvbnNlLlxuICAgKiBAcGFyYW0gY29kZSBUaGUgbmV3IHN0YXR1cyBjb2RlLlxuICAgKi9cbiAgcHVibGljIHNldFN0YXR1c0NvZGUoY29kZTogbnVtYmVyKSB7XG4gICAgdGhpcy5yZXNwb25zZS5zdGF0dXNDb2RlID0gY29kZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBQYWNrIGludG8gYSBidWZmZXIgZm9yIHRyYW5zbWlzc2lvbiB0byBNSVRNUHJveHkuXG4gICAqL1xuICBwdWJsaWMgdG9CdWZmZXIoKTogQnVmZmVyIHtcbiAgICBjb25zdCBtZXRhZGF0YSA9IEJ1ZmZlci5mcm9tKEpTT04uc3RyaW5naWZ5KHRoaXMucmVzcG9uc2UpLCAndXRmOCcpO1xuICAgIGNvbnN0IG1ldGFkYXRhTGVuZ3RoID0gbWV0YWRhdGEubGVuZ3RoO1xuICAgIGNvbnN0IHJlc3BvbnNlTGVuZ3RoID0gdGhpcy5fcmVzcG9uc2VCb2R5Lmxlbmd0aFxuICAgIGNvbnN0IHJ2ID0gQnVmZmVyLmFsbG9jKDggKyBtZXRhZGF0YUxlbmd0aCArIHJlc3BvbnNlTGVuZ3RoKTtcbiAgICBydi53cml0ZUludDMyTEUobWV0YWRhdGFMZW5ndGgsIDApO1xuICAgIHJ2LndyaXRlSW50MzJMRShyZXNwb25zZUxlbmd0aCwgNCk7XG4gICAgbWV0YWRhdGEuY29weShydiwgOCk7XG4gICAgdGhpcy5fcmVzcG9uc2VCb2R5LmNvcHkocnYsIDggKyBtZXRhZGF0YUxlbmd0aCk7XG4gICAgcmV0dXJuIHJ2O1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTdGFzaGVkSXRlbSB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHB1YmxpYyByZWFkb25seSByYXdVcmw6IHN0cmluZyxcbiAgICBwdWJsaWMgcmVhZG9ubHkgbWltZVR5cGU6IHN0cmluZyxcbiAgICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogQnVmZmVyKSB7fVxuXG4gIHB1YmxpYyBnZXQgc2hvcnRNaW1lVHlwZSgpOiBzdHJpbmcge1xuICAgIGxldCBtaW1lID0gdGhpcy5taW1lVHlwZS50b0xvd2VyQ2FzZSgpO1xuICAgIGlmIChtaW1lLmluZGV4T2YoXCI7XCIpICE9PSAtMSkge1xuICAgICAgbWltZSA9IG1pbWUuc2xpY2UoMCwgbWltZS5pbmRleE9mKFwiO1wiKSk7XG4gICAgfVxuICAgIHJldHVybiBtaW1lO1xuICB9XG5cbiAgcHVibGljIGdldCBpc0h0bWwoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMuc2hvcnRNaW1lVHlwZSA9PT0gXCJ0ZXh0L2h0bWxcIjtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgaXNKYXZhU2NyaXB0KCk6IGJvb2xlYW4ge1xuICAgIHN3aXRjaCh0aGlzLnNob3J0TWltZVR5cGUpIHtcbiAgICAgIGNhc2UgJ3RleHQvamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICdhcHBsaWNhdGlvbi9qYXZhc2NyaXB0JzpcbiAgICAgIGNhc2UgJ3RleHQveC1qYXZhc2NyaXB0JzpcbiAgICAgIGNhc2UgJ2FwcGxpY2F0aW9uL3gtamF2YXNjcmlwdCc6XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiBkZWZhdWx0U3Rhc2hGaWx0ZXIodXJsOiBzdHJpbmcsIGl0ZW06IFN0YXNoZWRJdGVtKTogYm9vbGVhbiB7XG4gIHJldHVybiBpdGVtLmlzSmF2YVNjcmlwdCB8fCBpdGVtLmlzSHRtbDtcbn1cblxuLyoqXG4gKiBDbGFzcyB0aGF0IGxhdW5jaGVzIE1JVE0gcHJveHkgYW5kIHRhbGtzIHRvIGl0IHZpYSBXZWJTb2NrZXRzLlxuICovXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNSVRNUHJveHkge1xuICBwcml2YXRlIHN0YXRpYyBfYWN0aXZlUHJvY2Vzc2VzOiBDaGlsZFByb2Nlc3NbXSA9IFtdO1xuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgbmV3IE1JVE1Qcm94eSBpbnN0YW5jZS5cbiAgICogQHBhcmFtIGNiIENhbGxlZCB3aXRoIGludGVyY2VwdGVkIEhUVFAgcmVxdWVzdHMgLyByZXNwb25zZXMuXG4gICAqIEBwYXJhbSBpbnRlcmNlcHRQYXRocyBMaXN0IG9mIHBhdGhzIHRvIGNvbXBsZXRlbHkgaW50ZXJjZXB0IHdpdGhvdXQgc2VuZGluZyB0byB0aGUgc2VydmVyIChlLmcuIFsnL2V2YWwnXSlcbiAgICogQHBhcmFtIHF1aWV0IElmIHRydWUsIGRvIG5vdCBwcmludCBkZWJ1Z2dpbmcgbWVzc2FnZXMgKGRlZmF1bHRzIHRvICd0cnVlJykuXG4gICAqIEBwYXJhbSBvbmx5SW50ZXJjZXB0VGV4dEZpbGVzIElmIHRydWUsIG9ubHkgaW50ZXJjZXB0IHRleHQgZmlsZXMgKEphdmFTY3JpcHQvSFRNTC9DU1MvZXRjLCBhbmQgaWdub3JlIG1lZGlhIGZpbGVzKS5cbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgYXN5bmMgQ3JlYXRlKGNiOiBJbnRlcmNlcHRvciA9IG5vcEludGVyY2VwdG9yLCBpbnRlcmNlcHRQYXRoczogc3RyaW5nW10gPSBbXSwgcXVpZXQ6IGJvb2xlYW4gPSB0cnVlLCBvbmx5SW50ZXJjZXB0VGV4dEZpbGVzID0gZmFsc2UsIGlnbm9yZUhvc3RzOiBzdHJpbmcgfCBudWxsID0gbnVsbCk6IFByb21pc2U8TUlUTVByb3h5PiB7XG4gICAgLy8gQ29uc3RydWN0IFdlYlNvY2tldCBzZXJ2ZXIsIGFuZCB3YWl0IGZvciBpdCB0byBiZWdpbiBsaXN0ZW5pbmcuXG4gICAgY29uc3Qgd3NzID0gbmV3IFdlYlNvY2tldFNlcnZlcih7IHBvcnQ6IDg3NjUgfSk7XG4gICAgY29uc3QgcHJveHlDb25uZWN0ZWQgPSBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB3c3Mub25jZSgnY29ubmVjdGlvbicsICgpID0+IHtcbiAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gICAgY29uc3QgbXAgPSBuZXcgTUlUTVByb3h5KGNiLCBvbmx5SW50ZXJjZXB0VGV4dEZpbGVzKTtcbiAgICAvLyBTZXQgdXAgV1NTIGNhbGxiYWNrcyBiZWZvcmUgTUlUTVByb3h5IGNvbm5lY3RzLlxuICAgIG1wLl9pbml0aWFsaXplV1NTKHdzcyk7XG4gICAgYXdhaXQgbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgd3NzLm9uY2UoJ2xpc3RlbmluZycsICgpID0+IHtcbiAgICAgICAgd3NzLnJlbW92ZUxpc3RlbmVyKCdlcnJvcicsIHJlamVjdCk7XG4gICAgICAgIHJlc29sdmUoKTtcbiAgICAgIH0pO1xuICAgICAgd3NzLm9uY2UoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICB9KTtcblxuICAgIHRyeSB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB3YWl0Rm9yUG9ydCg4MDgwLCAxKTtcbiAgICAgICAgaWYgKCFxdWlldCkge1xuICAgICAgICAgIGNvbnNvbGUubG9nKGBNSVRNUHJveHkgYWxyZWFkeSBydW5uaW5nLmApO1xuICAgICAgICB9XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmICghcXVpZXQpIHtcbiAgICAgICAgICBjb25zb2xlLmxvZyhgTUlUTVByb3h5IG5vdCBydW5uaW5nOyBzdGFydGluZyB1cCBtaXRtcHJveHkuYCk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gU3RhcnQgdXAgTUlUTSBwcm9jZXNzLlxuICAgICAgICAvLyAtLWFudGljYWNoZSBtZWFucyB0byBkaXNhYmxlIGNhY2hpbmcsIHdoaWNoIGdldHMgaW4gdGhlIHdheSBvZiB0cmFuc3BhcmVudGx5IHJld3JpdGluZyBjb250ZW50LlxuICAgICAgICBjb25zdCBzY3JpcHRBcmdzID0gaW50ZXJjZXB0UGF0aHMubGVuZ3RoID4gMCA/IFtcIi0tc2V0XCIsIGBpbnRlcmNlcHQ9JHtpbnRlcmNlcHRQYXRocy5qb2luKFwiLFwiKX1gXSA6IFtdO1xuICAgICAgICBzY3JpcHRBcmdzLnB1c2goXCItLXNldFwiLCBgb25seUludGVyY2VwdFRleHRGaWxlcz0ke29ubHlJbnRlcmNlcHRUZXh0RmlsZXN9YCk7XG4gICAgICAgIGlmIChpZ25vcmVIb3N0cykge1xuICAgICAgICAgIHNjcmlwdEFyZ3MucHVzaChgLS1pZ25vcmUtaG9zdHNgLCBpZ25vcmVIb3N0cyk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBvcHRpb25zID0gW1wiLS1hbnRpY2FjaGVcIiwgXCItc1wiLCByZXNvbHZlKF9fZGlybmFtZSwgYC4uL3NjcmlwdHMvcHJveHkucHlgKV0uY29uY2F0KHNjcmlwdEFyZ3MpO1xuICAgICAgICBpZiAocXVpZXQpIHtcbiAgICAgICAgICBvcHRpb25zLnB1c2goJy1xJyk7XG4gICAgICAgIH1cbiAgICAgICAgXG4gICAgICAgIC8vIGFsbG93IHNlbGYtc2lnbmVkIFNTTCBjZXJ0aWZpY2F0ZXNcbiAgICAgICAgb3B0aW9ucy5wdXNoKFwiLS1zc2wtaW5zZWN1cmVcIik7XG4gICAgICAgIFxuICAgICAgICBjb25zdCBtaXRtUHJvY2VzcyA9IHNwYXduKFwibWl0bWR1bXBcIiwgb3B0aW9ucywge1xuICAgICAgICAgIHN0ZGlvOiAnaW5oZXJpdCdcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IG1pdG1Qcm94eUV4aXRlZCA9IG5ldyBQcm9taXNlPHZvaWQ+KChfLCByZWplY3QpID0+IHtcbiAgICAgICAgICBtaXRtUHJvY2Vzcy5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgICAgICAgbWl0bVByb2Nlc3Mub25jZSgnZXhpdCcsIHJlamVjdCk7XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoTUlUTVByb3h5Ll9hY3RpdmVQcm9jZXNzZXMucHVzaChtaXRtUHJvY2VzcykgPT09IDEpIHtcbiAgICAgICAgICBwcm9jZXNzLm9uKCdTSUdJTlQnLCBNSVRNUHJveHkuX2NsZWFudXApO1xuICAgICAgICAgIHByb2Nlc3Mub24oJ2V4aXQnLCBNSVRNUHJveHkuX2NsZWFudXApO1xuICAgICAgICB9XG4gICAgICAgIG1wLl9pbml0aWFsaXplTUlUTVByb3h5KG1pdG1Qcm9jZXNzKTtcbiAgICAgICAgLy8gV2FpdCBmb3IgcG9ydCA4MDgwIHRvIGNvbWUgb25saW5lLlxuICAgICAgICBjb25zdCB3YWl0aW5nRm9yUG9ydCA9IHdhaXRGb3JQb3J0KDgwODApO1xuICAgICAgICB0cnkge1xuICAgICAgICAgIC8vIEZhaWxzIGlmIG1pdG1wcm94eSBleGl0cyBiZWZvcmUgcG9ydCBiZWNvbWVzIGF2YWlsYWJsZS5cbiAgICAgICAgICBhd2FpdCBQcm9taXNlLnJhY2UoW21pdG1Qcm94eUV4aXRlZCwgd2FpdGluZ0ZvclBvcnRdKTtcbiAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgIGlmIChlICYmIHR5cGVvZihlKSA9PT0gJ29iamVjdCcgJiYgZS5jb2RlID09PSBcIkVOT0VOVFwiKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYG1pdG1kdW1wLCB3aGljaCBpcyBhbiBleGVjdXRhYmxlIHRoYXQgc2hpcHMgd2l0aCBtaXRtcHJveHksIGlzIG5vdCBvbiB5b3VyIFBBVEguIFBsZWFzZSBlbnN1cmUgdGhhdCB5b3UgY2FuIHJ1biBtaXRtZHVtcCAtLXZlcnNpb24gc3VjY2Vzc2Z1bGx5IGZyb20geW91ciBjb21tYW5kIGxpbmUuYClcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBVbmFibGUgdG8gc3RhcnQgbWl0bXByb3h5OiAke2V9YCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBhd2FpdCBwcm94eUNvbm5lY3RlZDtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBhd2FpdCBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlKSA9PiB3c3MuY2xvc2UocmVzb2x2ZSkpO1xuICAgICAgdGhyb3cgZTtcbiAgICB9XG5cbiAgICByZXR1cm4gbXA7XG4gIH1cblxuICBwcml2YXRlIHN0YXRpYyBfY2xlYW51cENhbGxlZCA9IGZhbHNlO1xuICBwcml2YXRlIHN0YXRpYyBfY2xlYW51cCgpOiB2b2lkIHtcbiAgICBpZiAoTUlUTVByb3h5Ll9jbGVhbnVwQ2FsbGVkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIE1JVE1Qcm94eS5fY2xlYW51cENhbGxlZCA9IHRydWU7XG4gICAgTUlUTVByb3h5Ll9hY3RpdmVQcm9jZXNzZXMuZm9yRWFjaCgocCkgPT4ge1xuICAgICAgcC5raWxsKCdTSUdLSUxMJyk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zdGFzaEVuYWJsZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbiAgLy8gVG9nZ2xlIHdoZXRoZXIgb3Igbm90IG1pdG1wcm94eS1ub2RlIHN0YXNoZXMgbW9kaWZpZWQgc2VydmVyIHJlc3BvbnNlcy5cbiAgLy8gKipOb3QgdXNlZCBmb3IgcGVyZm9ybWFuY2UqKiwgYnV0IGVuYWJsZXMgTm9kZS5qcyBjb2RlIHRvIGZldGNoIHByZXZpb3VzIHNlcnZlciByZXNwb25zZXMgZnJvbSB0aGUgcHJveHkuXG4gIHB1YmxpYyBnZXQgc3Rhc2hFbmFibGVkKCk6IGJvb2xlYW4ge1xuICAgIHJldHVybiB0aGlzLl9zdGFzaEVuYWJsZWQ7XG4gIH1cbiAgcHVibGljIHNldCBzdGFzaEVuYWJsZWQodjogYm9vbGVhbikge1xuICAgIGlmICghdikge1xuICAgICAgdGhpcy5fc3Rhc2guY2xlYXIoKTtcbiAgICB9XG4gICAgdGhpcy5fc3Rhc2hFbmFibGVkID0gdjtcbiAgfVxuICBwcml2YXRlIF9taXRtUHJvY2VzczogQ2hpbGRQcm9jZXNzID0gbnVsbDtcbiAgcHJpdmF0ZSBfbWl0bUVycm9yOiBFcnJvciA9IG51bGw7XG4gIHByaXZhdGUgX3dzczogV2ViU29ja2V0U2VydmVyID0gbnVsbDtcbiAgcHVibGljIGNiOiBJbnRlcmNlcHRvcjtcbiAgcHVibGljIHJlYWRvbmx5IG9ubHlJbnRlcmNlcHRUZXh0RmlsZXM6IGJvb2xlYW47XG4gIHByaXZhdGUgX3N0YXNoID0gbmV3IE1hcDxzdHJpbmcsIFN0YXNoZWRJdGVtPigpO1xuICBwcml2YXRlIF9zdGFzaEZpbHRlcjogKHVybDogc3RyaW5nLCBpdGVtOiBTdGFzaGVkSXRlbSkgPT4gYm9vbGVhbiA9IGRlZmF1bHRTdGFzaEZpbHRlcjtcbiAgcHVibGljIGdldCBzdGFzaEZpbHRlcigpOiAodXJsOiBzdHJpbmcsIGl0ZW06IFN0YXNoZWRJdGVtKSA9PiBib29sZWFuIHtcbiAgICByZXR1cm4gdGhpcy5fc3Rhc2hGaWx0ZXI7XG4gIH1cbiAgcHVibGljIHNldCBzdGFzaEZpbHRlcih2YWx1ZTogKHVybDogc3RyaW5nLCBpdGVtOiBTdGFzaGVkSXRlbSkgPT4gYm9vbGVhbikge1xuICAgIGlmICh0eXBlb2YodmFsdWUpID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICB0aGlzLl9zdGFzaEZpbHRlciA9IHZhbHVlO1xuICAgIH0gZWxzZSBpZiAodmFsdWUgPT09IG51bGwpIHtcbiAgICAgIHRoaXMuX3N0YXNoRmlsdGVyID0gZGVmYXVsdFN0YXNoRmlsdGVyO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEludmFsaWQgc3Rhc2ggZmlsdGVyOiBFeHBlY3RlZCBhIGZ1bmN0aW9uLmApO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgY29uc3RydWN0b3IoY2I6IEludGVyY2VwdG9yLCBvbmx5SW50ZXJjZXB0VGV4dEZpbGVzOiBib29sZWFuKSB7XG4gICAgdGhpcy5jYiA9IGNiO1xuICAgIHRoaXMub25seUludGVyY2VwdFRleHRGaWxlcyA9IG9ubHlJbnRlcmNlcHRUZXh0RmlsZXM7XG4gIH1cblxuICBwcml2YXRlIF9pbml0aWFsaXplV1NTKHdzczogV2ViU29ja2V0U2VydmVyKTogdm9pZCB7XG4gICAgdGhpcy5fd3NzID0gd3NzO1xuICAgIHRoaXMuX3dzcy5vbignY29ubmVjdGlvbicsICh3cykgPT4ge1xuICAgICAgd3Mub24oJ2Vycm9yJywgKGUpID0+IHtcbiAgICAgICAgaWYgKChlIGFzIGFueSkuY29kZSAhPT0gXCJFQ09OTlJFU0VUXCIpIHtcbiAgICAgICAgICBjb25zb2xlLmxvZyhgV2ViU29ja2V0IGVycm9yOiAke2V9YCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgICAgd3Mub24oJ21lc3NhZ2UnLCBhc3luYyAobWVzc2FnZTogQnVmZmVyKSA9PiB7XG4gICAgICAgIGNvbnN0IG9yaWdpbmFsID0gSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZS5Gcm9tQnVmZmVyKG1lc3NhZ2UpO1xuICAgICAgICBjb25zdCBydiA9IHRoaXMuY2Iob3JpZ2luYWwpO1xuICAgICAgICBpZiAocnYgJiYgdHlwZW9mKHJ2KSA9PT0gJ29iamVjdCcgJiYgcnYudGhlbikge1xuICAgICAgICAgIGF3YWl0IHJ2O1xuICAgICAgICB9XG4gICAgICAgIC8vIFJlbW92ZSB0cmFuc2Zlci1lbmNvZGluZy4gV2UgZG9uJ3Qgc3VwcG9ydCBjaHVua2VkLlxuICAgICAgICBpZiAodGhpcy5fc3Rhc2hFbmFibGVkKSB7XG4gICAgICAgICAgY29uc3QgaXRlbSA9IG5ldyBTdGFzaGVkSXRlbShvcmlnaW5hbC5yZXF1ZXN0LnJhd1VybCwgb3JpZ2luYWwucmVzcG9uc2UuZ2V0SGVhZGVyKCdjb250ZW50LXR5cGUnKSwgb3JpZ2luYWwucmVzcG9uc2VCb2R5KTtcbiAgICAgICAgICBpZiAodGhpcy5fc3Rhc2hGaWx0ZXIob3JpZ2luYWwucmVxdWVzdC5yYXdVcmwsIGl0ZW0pKSB7XG4gICAgICAgICAgICB0aGlzLl9zdGFzaC5zZXQob3JpZ2luYWwucmVxdWVzdC5yYXdVcmwsIGl0ZW0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICB3cy5zZW5kKG9yaWdpbmFsLnRvQnVmZmVyKCkpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9pbml0aWFsaXplTUlUTVByb3h5KG1pdG1Qcm94eTogQ2hpbGRQcm9jZXNzKTogdm9pZCB7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3MgPSBtaXRtUHJveHk7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3Mub24oJ2V4aXQnLCAoY29kZSwgc2lnbmFsKSA9PiB7XG4gICAgICBjb25zdCBpbmRleCA9IE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLmluZGV4T2YodGhpcy5fbWl0bVByb2Nlc3MpO1xuICAgICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgICBNSVRNUHJveHkuX2FjdGl2ZVByb2Nlc3Nlcy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgICAgfVxuICAgICAgaWYgKGNvZGUgIT09IG51bGwpIHtcbiAgICAgICAgaWYgKGNvZGUgIT09IDApIHtcbiAgICAgICAgICB0aGlzLl9taXRtRXJyb3IgPSBuZXcgRXJyb3IoYFByb2Nlc3MgZXhpdGVkIHdpdGggY29kZSAke2NvZGV9LmApO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9taXRtRXJyb3IgPSBuZXcgRXJyb3IoYFByb2Nlc3MgZXhpdGVkIGR1ZSB0byBzaWduYWwgJHtzaWduYWx9LmApO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHRoaXMuX21pdG1Qcm9jZXNzLm9uKCdlcnJvcicsIChlcnIpID0+IHtcbiAgICAgIHRoaXMuX21pdG1FcnJvciA9IGVycjtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZXMgdGhlIGdpdmVuIFVSTCBmcm9tIHRoZSBzdGFzaC5cbiAgICogQHBhcmFtIHVybFxuICAgKi9cbiAgcHVibGljIGdldEZyb21TdGFzaCh1cmw6IHN0cmluZyk6IFN0YXNoZWRJdGVtIHtcbiAgICByZXR1cm4gdGhpcy5fc3Rhc2guZ2V0KHVybCk7XG4gIH1cblxuICBwdWJsaWMgZm9yRWFjaFN0YXNoSXRlbShjYjogKHZhbHVlOiBTdGFzaGVkSXRlbSwgdXJsOiBzdHJpbmcpID0+IHZvaWQpOiB2b2lkIHtcbiAgICB0aGlzLl9zdGFzaC5mb3JFYWNoKGNiKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXF1ZXN0cyB0aGUgZ2l2ZW4gVVJMIGZyb20gdGhlIHByb3h5LlxuICAgKi9cbiAgcHVibGljIGFzeW5jIHByb3h5R2V0KHVybFN0cmluZzogc3RyaW5nKTogUHJvbWlzZTxIVFRQUmVzcG9uc2U+IHtcbiAgICBjb25zdCB1cmwgPSBwYXJzZVVSTCh1cmxTdHJpbmcpO1xuICAgIGNvbnN0IGdldCA9IHVybC5wcm90b2NvbCA9PT0gXCJodHRwOlwiID8gaHR0cEdldCA6IGh0dHBzR2V0O1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxIVFRQUmVzcG9uc2U+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IHJlcSA9IGdldCh7XG4gICAgICAgIHVybDogdXJsU3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgaG9zdDogdXJsLmhvc3RcbiAgICAgICAgfSxcbiAgICAgICAgaG9zdDogJ2xvY2FsaG9zdCcsXG4gICAgICAgIHBvcnQ6IDgwODAsXG4gICAgICAgIHBhdGg6IHVybFN0cmluZ1xuICAgICAgfSwgKHJlcykgPT4ge1xuICAgICAgICBjb25zdCBkYXRhID0gbmV3IEFycmF5PEJ1ZmZlcj4oKTtcbiAgICAgICAgcmVzLm9uKCdkYXRhJywgKGNodW5rOiBCdWZmZXIpID0+IHtcbiAgICAgICAgICBkYXRhLnB1c2goY2h1bmspO1xuICAgICAgICB9KTtcbiAgICAgICAgcmVzLm9uKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgICAgY29uc3QgZCA9IEJ1ZmZlci5jb25jYXQoZGF0YSk7XG4gICAgICAgICAgcmVzb2x2ZSh7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiByZXMuc3RhdHVzQ29kZSxcbiAgICAgICAgICAgIGhlYWRlcnM6IHJlcy5oZWFkZXJzLFxuICAgICAgICAgICAgYm9keTogZFxuICAgICAgICAgIH0gYXMgSFRUUFJlc3BvbnNlKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJlcy5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgICB9KTtcbiAgICAgIHJlcS5vbmNlKCdlcnJvcicsIHJlamVjdCk7XG4gICAgfSk7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgc2h1dGRvd24oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IGNsb3NlV1NTID0gKCkgPT4ge1xuICAgICAgICB0aGlzLl93c3MuY2xvc2UoKGVycikgPT4ge1xuICAgICAgICAgIGlmIChlcnIpIHtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH07XG5cbiAgICAgIGlmICh0aGlzLl9taXRtUHJvY2VzcyAmJiAhdGhpcy5fbWl0bVByb2Nlc3Mua2lsbGVkKSB7XG4gICAgICAgIHRoaXMuX21pdG1Qcm9jZXNzLm9uY2UoJ2V4aXQnLCAoY29kZSwgc2lnbmFsKSA9PiB7XG4gICAgICAgICAgY2xvc2VXU1MoKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHRoaXMuX21pdG1Qcm9jZXNzLmtpbGwoJ1NJR1RFUk0nKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNsb3NlV1NTKCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn1cbiJdfQ==