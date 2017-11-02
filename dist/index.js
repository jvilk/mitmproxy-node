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
                // --anticache means to disable caching, which gets in the way of transparently rewriting content.
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQUFBLDJCQUE2QztBQUM3QyxpREFBa0Q7QUFDbEQsK0JBQTZCO0FBQzdCLDZCQUEyQztBQUMzQywrQkFBb0M7QUFDcEMsaUNBQXNDO0FBQ3RDLDZCQUE2QztBQUU3Qzs7Ozs7R0FLRztBQUNILHFCQUFxQixJQUFZLEVBQUUsVUFBa0IsRUFBRSxFQUFFLFdBQW1CLEdBQUc7SUFDN0UsTUFBTSxDQUFDLElBQUksT0FBTyxDQUFPLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1FBQzNDLElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDO1FBQy9CLElBQUksYUFBYSxHQUFHLFFBQVEsQ0FBQztRQUM3QixJQUFJLEtBQUssR0FBaUIsSUFBSSxDQUFDO1FBQy9CLElBQUksTUFBTSxHQUFXLElBQUksQ0FBQztRQUUxQjtZQUNFLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUNwQixLQUFLLEdBQUcsSUFBSSxDQUFDO1lBQ2IsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDO2dCQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUM3QixNQUFNLEdBQUcsSUFBSSxDQUFDO1FBQ2hCLENBQUM7UUFFRDtZQUNFLFlBQVksRUFBRSxDQUFDO1FBQ2pCLENBQUM7UUFFRDtZQUNFLDBCQUEwQixFQUFFLENBQUM7WUFFN0IsRUFBRSxDQUFDLENBQUMsRUFBRSxnQkFBZ0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMzQixNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDO1lBQ3RDLENBQUM7WUFFRCxNQUFNLEdBQUcsc0JBQWdCLENBQUMsSUFBSSxFQUFFLFdBQVcsRUFBRTtnQkFDM0MsMEJBQTBCLEVBQUUsQ0FBQztnQkFDN0IsRUFBRSxDQUFDLENBQUMsZ0JBQWdCLElB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QUFDO0tBQUE7SUFFWSxRQUFROztZQUNuQixNQUFNLENBQUMsSUFBSSxPQUFPLENBQU8sQ0FBQyxPQUFPLEVBQUUsTUFBTSxFQUFFLEVBQUU7Z0JBQzNDLE1BQU0sUUFBUSxHQUFHLEdBQUcsRUFBRTtvQkFDcEIsSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRTt3QkFDdEIsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQzs0QkFDUixNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7d0JBQ2QsQ0FBQzt3QkFBQyxJQUFJLENBQUMsQ0FBQzs0QkFDTixPQUFPLEVBQUUsQ0FBQzt3QkFDWixDQUFDO29CQUNILENBQUMsQ0FBQyxDQUFDO2dCQUNMLENBQUMsQ0FBQztnQkFFRixFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsWUFBWSxJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQztvQkFDckQsSUFBSSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sRUFBRSxFQUFFO3dCQUM5QyxRQUFRLEVBQUUsQ0FBQztvQkFDYixDQUFDLENBQUMsQ0FBQztvQkFDSCxJQUFJLENBQUMsWUFBWSxDQUFDLElBQUksRUFBRSxDQUFDO2dCQUMzQixDQUFDO2dCQUFDLElBQUksQ0FBQyxDQUFDO29CQUNOLFFBQVEsRUFBRSxDQUFDO2dCQUNiLENBQUM7WUFDSCxDQUFDLENBQUMsQ0FBQztRQUNMLENBQUM7S0FBQTs7QUFwTGMsMEJBQWdCLEdBQW1CLEVBQUUsQ0FBQztBQTRDdEMsd0JBQWMsR0FBRyxLQUFLLENBQUM7QUE3Q3hDLDRCQXNMQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7U2VydmVyIGFzIFdlYlNvY2tldFNlcnZlcn0gZnJvbSAnd3MnO1xuaW1wb3J0IHtzcGF3biwgQ2hpbGRQcm9jZXNzfSBmcm9tICdjaGlsZF9wcm9jZXNzJztcbmltcG9ydCB7cmVzb2x2ZX0gZnJvbSAncGF0aCc7XG5pbXBvcnQge3BhcnNlIGFzIHBhcnNlVVJMLCBVcmx9IGZyb20gJ3VybCc7XG5pbXBvcnQge2dldCBhcyBodHRwR2V0fSBmcm9tICdodHRwJztcbmltcG9ydCB7Z2V0IGFzIGh0dHBzR2V0fSBmcm9tICdodHRwcyc7XG5pbXBvcnQge2NyZWF0ZUNvbm5lY3Rpb24sIFNvY2tldH0gZnJvbSAnbmV0JztcblxuLyoqXG4gKiBXYWl0IGZvciB0aGUgc3BlY2lmaWVkIHBvcnQgdG8gb3Blbi5cbiAqIEBwYXJhbSBwb3J0IFRoZSBwb3J0IHRvIHdhdGNoIGZvci5cbiAqIEBwYXJhbSByZXRyaWVzIFRoZSBudW1iZXIgb2YgdGltZXMgdG8gcmV0cnkgYmVmb3JlIGdpdmluZyB1cC4gRGVmYXVsdHMgdG8gMTAuXG4gKiBAcGFyYW0gaW50ZXJ2YWwgVGhlIGludGVydmFsIGJldHdlZW4gcmV0cmllcywgaW4gbWlsbGlzZWNvbmRzLiBEZWZhdWx0cyB0byA1MDAuXG4gKi9cbmZ1bmN0aW9uIHdhaXRGb3JQb3J0KHBvcnQ6IG51bWJlciwgcmV0cmllczogbnVtYmVyID0gMTAsIGludGVydmFsOiBudW1iZXIgPSA1MDApOiBQcm9taXNlPHZvaWQ+IHtcbiAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBsZXQgcmV0cmllc1JlbWFpbmluZyA9IHJldHJpZXM7XG4gICAgbGV0IHJldHJ5SW50ZXJ2YWwgPSBpbnRlcnZhbDtcbiAgICBsZXQgdGltZXI6IE5vZGVKUy5UaW1lciA9IG51bGw7XG4gICAgbGV0IHNvY2tldDogU29ja2V0ID0gbnVsbDtcblxuICAgIGZ1bmN0aW9uIGNsZWFyVGltZXJBbmREZXN0cm95U29ja2V0KCkge1xuICAgICAgY2xlYXJUaW1lb3V0KHRpbWVyKTtcbiAgICAgIHRpbWVyID0gbnVsbDtcbiAgICAgIGlmIChzb2NrZXQpIHNvY2tldC5kZXN0cm95KCk7XG4gICAgICBzb2NrZXQgPSBudWxsO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJldHJ5KCkge1xuICAgICAgdHJ5VG9Db25uZWN0KCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdHJ5VG9Db25uZWN0KCkge1xuICAgICAgY2xlYXJUaW1lckFuZERlc3Ryb3lTb2NrZXQoKTtcblxuICAgICAgaWYgKC0tcmV0cmllc1JlbWFpbmluZyA8IDApIHtcbiAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignb3V0IG9mIHJldHJpZXMnKSk7XG4gICAgICB9XG5cbiAgICAgIHNvY2tldCA9IGNyZWF0ZUNvbm5lY3Rpb24ocG9ydCwgXCJsb2NhbGhvc3RcIiwgZnVuY3Rpb24oKSB7XG4gICAgICAgIGNsZWFyVGltZXJBbmREZXN0cm95U29ja2V0KCk7XG4gICAgICAgIGlmIChyZXRyaWVzUmVtYWluaW5nID49IDApIHJlc29sdmUoKTtcbiAgICAgIH0pO1xuXG4gICAgICB0aW1lciA9IHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7IHJldHJ5KCk7IH0sIHJldHJ5SW50ZXJ2YWwpO1xuXG4gICAgICBzb2NrZXQub24oJ2Vycm9yJywgZnVuY3Rpb24oZXJyKSB7XG4gICAgICAgIGNsZWFyVGltZXJBbmREZXN0cm95U29ja2V0KCk7XG4gICAgICAgIHNldFRpbWVvdXQocmV0cnksIHJldHJ5SW50ZXJ2YWwpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdHJ5VG9Db25uZWN0KCk7XG4gIH0pO1xufVxuXG4vKipcbiAqIEZ1bmN0aW9uIHRoYXQgaW50ZXJjZXB0cyBhbmQgcmV3cml0ZXMgSFRUUCByZXNwb25zZXMuXG4gKi9cbmV4cG9ydCB0eXBlIEludGVyY2VwdG9yID0gKG06IEludGVyY2VwdGVkSFRUUE1lc3NhZ2UpID0+IHZvaWQ7XG5cbi8qKlxuICogQW4gaW50ZXJjZXB0b3IgdGhhdCBkb2VzIG5vdGhpbmcuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBub3BJbnRlcmNlcHRvcihtOiBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlKTogdm9pZCB7fVxuXG4vKipcbiAqIFRoZSBjb3JlIEhUVFAgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSFRUUFJlc3BvbnNlIHtcbiAgc3RhdHVzQ29kZTogbnVtYmVyLFxuICBoZWFkZXJzOiB7W25hbWU6IHN0cmluZ106IHN0cmluZ307XG4gIGJvZHk6IEJ1ZmZlcjtcbn1cblxuLyoqXG4gKiBNZXRhZGF0YSBhc3NvY2lhdGVkIHdpdGggYSByZXF1ZXN0L3Jlc3BvbnNlIHBhaXIuXG4gKi9cbmludGVyZmFjZSBIVFRQTWVzc2FnZU1ldGFkYXRhIHtcbiAgcmVxdWVzdDogSFRUUFJlcXVlc3RNZXRhZGF0YTtcbiAgcmVzcG9uc2U6IEhUVFBSZXNwb25zZU1ldGFkYXRhO1xufVxuXG4vKipcbiAqIE1ldGFkYXRhIGFzc29jaWF0ZWQgd2l0aCBhbiBIVFRQIHJlcXVlc3QuXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSFRUUFJlcXVlc3RNZXRhZGF0YSB7XG4gIC8vIEdFVCwgREVMRVRFLCBQT1NULCAgZXRjLlxuICBtZXRob2Q6IHN0cmluZztcbiAgLy8gVGFyZ2V0IFVSTCBmb3IgdGhlIHJlcXVlc3QuXG4gIHVybDogc3RyaW5nO1xuICAvLyBUaGUgc2V0IG9mIGhlYWRlcnMgZnJvbSB0aGUgcmVxdWVzdCwgYXMga2V5LXZhbHVlIHBhaXJzLlxuICAvLyBTaW5jZSBoZWFkZXIgZmllbGRzIG1heSBiZSByZXBlYXRlZCwgdGhpcyBhcnJheSBtYXkgY29udGFpbiBtdWx0aXBsZSBlbnRyaWVzIGZvciB0aGUgc2FtZSBrZXkuXG4gIGhlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXTtcbn1cblxuLyoqXG4gKiBNZXRhZGF0YSBhc3NvY2lhdGVkIHdpdGggYW4gSFRUUCByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBIVFRQUmVzcG9uc2VNZXRhZGF0YSB7XG4gIC8vIFRoZSBudW1lcmljYWwgc3RhdHVzIGNvZGUuXG4gIHN0YXR1c19jb2RlOiBudW1iZXI7XG4gIC8vIFRoZSBzZXQgb2YgaGVhZGVycyBmcm9tIHRoZSByZXNwb25zZSwgYXMga2V5LXZhbHVlIHBhaXJzLlxuICAvLyBTaW5jZSBoZWFkZXIgZmllbGRzIG1heSBiZSByZXBlYXRlZCwgdGhpcyBhcnJheSBtYXkgY29udGFpbiBtdWx0aXBsZSBlbnRyaWVzIGZvciB0aGUgc2FtZSBrZXkuXG4gIGhlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXTtcbn1cblxuLyoqXG4gKiBBYnN0cmFjdCBjbGFzcyB0aGF0IHJlcHJlc2VudHMgSFRUUCBoZWFkZXJzLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQWJzdHJhY3RIVFRQSGVhZGVycyB7XG4gIHByaXZhdGUgX2hlYWRlcnM6IFtzdHJpbmcsIHN0cmluZ11bXTtcbiAgLy8gVGhlIHJhdyBoZWFkZXJzLCBhcyBhIHNlcXVlbmNlIG9mIGtleS92YWx1ZSBwYWlycy5cbiAgLy8gU2luY2UgaGVhZGVyIGZpZWxkcyBtYXkgYmUgcmVwZWF0ZWQsIHRoaXMgYXJyYXkgbWF5IGNvbnRhaW4gbXVsdGlwbGUgZW50cmllcyBmb3IgdGhlIHNhbWUga2V5LlxuICBwdWJsaWMgZ2V0IGhlYWRlcnMoKTogW3N0cmluZywgc3RyaW5nXVtdIHtcbiAgICByZXR1cm4gdGhpcy5faGVhZGVycztcbiAgfVxuICBjb25zdHJ1Y3RvcihoZWFkZXJzOiBbc3RyaW5nLCBzdHJpbmddW10pIHtcbiAgICB0aGlzLl9oZWFkZXJzID0gaGVhZGVycztcbiAgfVxuXG4gIHByaXZhdGUgX2luZGV4T2ZIZWFkZXIobmFtZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICBjb25zdCBoZWFkZXJzID0gdGhpcy5oZWFkZXJzO1xuICAgIGNvbnN0IGxlbiA9IGhlYWRlcnMubGVuZ3RoO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIGlmIChoZWFkZXJzW2ldWzBdLnRvTG93ZXJDYXNlKCkgPT09IG5hbWUpIHtcbiAgICAgICAgcmV0dXJuIGk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiAtMTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIHZhbHVlIG9mIHRoZSBnaXZlbiBoZWFkZXIgZmllbGQuXG4gICAqIElmIHRoZXJlIGFyZSBtdWx0aXBsZSBmaWVsZHMgd2l0aCB0aGF0IG5hbWUsIHRoaXMgb25seSByZXR1cm5zIHRoZSBmaXJzdCBmaWVsZCdzIHZhbHVlIVxuICAgKiBAcGFyYW0gbmFtZSBOYW1lIG9mIHRoZSBoZWFkZXIgZmllbGRcbiAgICovXG4gIHB1YmxpYyBnZXRIZWFkZXIobmFtZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgICBjb25zdCBpbmRleCA9IHRoaXMuX2luZGV4T2ZIZWFkZXIobmFtZS50b0xvd2VyQ2FzZSgpKTtcbiAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICByZXR1cm4gdGhpcy5oZWFkZXJzW2luZGV4XVsxXTtcbiAgICB9XG4gICAgcmV0dXJuICcnO1xuICB9XG5cbiAgLyoqXG4gICAqIFNldCB0aGUgdmFsdWUgb2YgdGhlIGdpdmVuIGhlYWRlciBmaWVsZC4gQXNzdW1lcyB0aGF0IHRoZXJlIGlzIG9ubHkgb25lIGZpZWxkIHdpdGggdGhlIGdpdmVuIG5hbWUuXG4gICAqIElmIHRoZSBmaWVsZCBkb2VzIG5vdCBleGlzdCwgaXQgYWRkcyBhIG5ldyBmaWVsZCB3aXRoIHRoZSBuYW1lIGFuZCB2YWx1ZS5cbiAgICogQHBhcmFtIG5hbWUgTmFtZSBvZiB0aGUgZmllbGQuXG4gICAqIEBwYXJhbSB2YWx1ZSBOZXcgdmFsdWUuXG4gICAqL1xuICBwdWJsaWMgc2V0SGVhZGVyKG5hbWU6IHN0cmluZywgdmFsdWU6IHN0cmluZyk6IHZvaWQge1xuICAgIGNvbnN0IGluZGV4ID0gdGhpcy5faW5kZXhPZkhlYWRlcihuYW1lLnRvTG93ZXJDYXNlKCkpO1xuICAgIGlmIChpbmRleCAhPT0gLTEpIHtcbiAgICAgIHRoaXMuaGVhZGVyc1tpbmRleF1bMV0gPSB2YWx1ZTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5oZWFkZXJzLnB1c2goW25hbWUsIHZhbHVlXSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgdGhlIGhlYWRlciBmaWVsZCB3aXRoIHRoZSBnaXZlbiBuYW1lLiBBc3N1bWVzIHRoYXQgdGhlcmUgaXMgb25seSBvbmUgZmllbGQgd2l0aCB0aGUgZ2l2ZW4gbmFtZS5cbiAgICogRG9lcyBub3RoaW5nIGlmIGZpZWxkIGRvZXMgbm90IGV4aXN0LlxuICAgKiBAcGFyYW0gbmFtZSBOYW1lIG9mIHRoZSBmaWVsZC5cbiAgICovXG4gIHB1YmxpYyByZW1vdmVIZWFkZXIobmFtZTogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3QgaW5kZXggPSB0aGlzLl9pbmRleE9mSGVhZGVyKG5hbWUudG9Mb3dlckNhc2UoKSk7XG4gICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgdGhpcy5oZWFkZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgYWxsIGhlYWRlciBmaWVsZHMuXG4gICAqL1xuICBwdWJsaWMgY2xlYXJIZWFkZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX2hlYWRlcnMgPSBbXTtcbiAgfVxufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYSBNSVRNLWVkIEhUVFAgcmVzcG9uc2UgZnJvbSBhIHNlcnZlci5cbiAqL1xuZXhwb3J0IGNsYXNzIEludGVyY2VwdGVkSFRUUFJlc3BvbnNlIGV4dGVuZHMgQWJzdHJhY3RIVFRQSGVhZGVycyB7XG4gIC8vIFRoZSBzdGF0dXMgY29kZSBvZiB0aGUgSFRUUCByZXNwb25zZS5cbiAgcHVibGljIHN0YXR1c0NvZGU6IG51bWJlcjtcblxuICBjb25zdHJ1Y3RvcihtZXRhZGF0YTogSFRUUFJlc3BvbnNlTWV0YWRhdGEpIHtcbiAgICBzdXBlcihtZXRhZGF0YS5oZWFkZXJzKTtcbiAgICB0aGlzLnN0YXR1c0NvZGUgPSBtZXRhZGF0YS5zdGF0dXNfY29kZTtcbiAgICAvLyBXZSBkb24ndCBzdXBwb3J0IGNodW5rZWQgdHJhbnNmZXJzLiBUaGUgcHJveHkgYWxyZWFkeSBkZS1jaHVua3MgaXQgZm9yIHVzLlxuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCd0cmFuc2Zlci1lbmNvZGluZycpO1xuICAgIC8vIE1JVE1Qcm94eSBkZWNvZGVzIHRoZSBkYXRhIGZvciB1cy5cbiAgICB0aGlzLnJlbW92ZUhlYWRlcignY29udGVudC1lbmNvZGluZycpO1xuICAgIC8vIENTUCBpcyBiYWQhXG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ2NvbnRlbnQtc2VjdXJpdHktcG9saWN5Jyk7XG4gICAgdGhpcy5yZW1vdmVIZWFkZXIoJ3gtd2Via2l0LWNzcCcpO1xuICAgIHRoaXMucmVtb3ZlSGVhZGVyKCd4LWNvbnRlbnQtc2VjdXJpdHktcG9saWN5Jyk7XG4gIH1cblxuICBwdWJsaWMgdG9KU09OKCk6IEhUVFBSZXNwb25zZU1ldGFkYXRhIHtcbiAgICByZXR1cm4ge1xuICAgICAgc3RhdHVzX2NvZGU6IHRoaXMuc3RhdHVzQ29kZSxcbiAgICAgIGhlYWRlcnM6IHRoaXMuaGVhZGVyc1xuICAgIH07XG4gIH1cbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIGFuIGludGVyY2VwdGVkIEhUVFAgcmVxdWVzdCBmcm9tIGEgY2xpZW50LlxuICovXG5leHBvcnQgY2xhc3MgSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdCBleHRlbmRzIEFic3RyYWN0SFRUUEhlYWRlcnMge1xuICAvLyBIVFRQIG1ldGhvZCAoR0VUL0RFTEVURS9ldGMpXG4gIHB1YmxpYyBtZXRob2Q6IHN0cmluZztcbiAgLy8gVGhlIFVSTCBhcyBhIHN0cmluZy5cbiAgcHVibGljIHJhd1VybDogc3RyaW5nO1xuICAvLyBUaGUgVVJMIGFzIGEgVVJMIG9iamVjdC5cbiAgcHVibGljIHVybDogVXJsO1xuXG4gIGNvbnN0cnVjdG9yKG1ldGFkYXRhOiBIVFRQUmVxdWVzdE1ldGFkYXRhKSB7XG4gICAgc3VwZXIobWV0YWRhdGEuaGVhZGVycyk7XG4gICAgdGhpcy5tZXRob2QgPSBtZXRhZGF0YS5tZXRob2QudG9Mb3dlckNhc2UoKTtcbiAgICB0aGlzLnJhd1VybCA9IG1ldGFkYXRhLnVybDtcbiAgICB0aGlzLnVybCA9IHBhcnNlVVJMKHRoaXMucmF3VXJsKTtcbiAgfVxufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYW4gaW50ZXJjZXB0ZWQgSFRUUCByZXF1ZXN0L3Jlc3BvbnNlIHBhaXIuXG4gKi9cbmV4cG9ydCBjbGFzcyBJbnRlcmNlcHRlZEhUVFBNZXNzYWdlIHtcbiAgLyoqXG4gICAqIFVucGFjayBmcm9tIGEgQnVmZmVyIHJlY2VpdmVkIGZyb20gTUlUTVByb3h5LlxuICAgKiBAcGFyYW0gYlxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBGcm9tQnVmZmVyKGI6IEJ1ZmZlcik6IEludGVyY2VwdGVkSFRUUE1lc3NhZ2Uge1xuICAgIGNvbnN0IG1ldGFkYXRhU2l6ZSA9IGIucmVhZEludDMyTEUoMCk7XG4gICAgY29uc3QgcmVxdWVzdFNpemUgPSBiLnJlYWRJbnQzMkxFKDQpO1xuICAgIGNvbnN0IHJlc3BvbnNlU2l6ZSA9IGIucmVhZEludDMyTEUoOCk7XG4gICAgY29uc3QgbWV0YWRhdGE6IEhUVFBNZXNzYWdlTWV0YWRhdGEgPSBKU09OLnBhcnNlKGIudG9TdHJpbmcoXCJ1dGY4XCIsIDEyLCAxMiArIG1ldGFkYXRhU2l6ZSkpO1xuICAgIHJldHVybiBuZXcgSW50ZXJjZXB0ZWRIVFRQTWVzc2FnZShcbiAgICAgIG5ldyBJbnRlcmNlcHRlZEhUVFBSZXF1ZXN0KG1ldGFkYXRhLnJlcXVlc3QpLFxuICAgICAgbmV3IEludGVyY2VwdGVkSFRUUFJlc3BvbnNlKG1ldGFkYXRhLnJlc3BvbnNlKSxcbiAgICAgIGIuc2xpY2UoMTIgKyBtZXRhZGF0YVNpemUsIDEyICsgbWV0YWRhdGFTaXplICsgcmVxdWVzdFNpemUpLFxuICAgICAgYi5zbGljZSgxMiArIG1ldGFkYXRhU2l6ZSArIHJlcXVlc3RTaXplLCAxMiArIG1ldGFkYXRhU2l6ZSArIHJlcXVlc3RTaXplICsgcmVzcG9uc2VTaXplKVxuICAgICk7XG4gIH1cblxuICBwdWJsaWMgcmVhZG9ubHkgcmVxdWVzdDogSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdDtcbiAgcHVibGljIHJlYWRvbmx5IHJlc3BvbnNlOiBJbnRlcmNlcHRlZEhUVFBSZXNwb25zZTtcbiAgLy8gVGhlIGJvZHkgb2YgdGhlIEhUVFAgcmVxdWVzdC5cbiAgcHVibGljIHJlYWRvbmx5IHJlcXVlc3RCb2R5OiBCdWZmZXI7XG4gIC8vIFRoZSBib2R5IG9mIHRoZSBIVFRQIHJlc3BvbnNlLiBSZWFkLW9ubHk7IGNoYW5nZSB0aGUgcmVzcG9uc2UgYm9keSB2aWEgc2V0UmVzcG9uc2VCb2R5LlxuICBwdWJsaWMgZ2V0IHJlc3BvbnNlQm9keSgpOiBCdWZmZXIge1xuICAgIHJldHVybiB0aGlzLl9yZXNwb25zZUJvZHk7XG4gIH1cbiAgcHJpdmF0ZSBfcmVzcG9uc2VCb2R5OiBCdWZmZXI7XG4gIHByaXZhdGUgY29uc3RydWN0b3IocmVxdWVzdDogSW50ZXJjZXB0ZWRIVFRQUmVxdWVzdCwgcmVzcG9uc2U6IEludGVyY2VwdGVkSFRUUFJlc3BvbnNlLCByZXF1ZXN0Qm9keTogQnVmZmVyLCByZXNwb25zZUJvZHk6IEJ1ZmZlcikge1xuICAgIHRoaXMucmVxdWVzdCA9IHJlcXVlc3Q7XG4gICAgdGhpcy5yZXNwb25zZSA9IHJlc3BvbnNlO1xuICAgIHRoaXMucmVxdWVzdEJvZHkgPSByZXF1ZXN0Qm9keTtcbiAgICB0aGlzLl9yZXNwb25zZUJvZHkgPSByZXNwb25zZUJvZHk7XG4gIH1cblxuICAvKipcbiAgICogQ2hhbmdlcyB0aGUgYm9keSBvZiB0aGUgSFRUUCByZXNwb25zZS4gQXBwcm9wcmlhdGVseSB1cGRhdGVzIGNvbnRlbnQtbGVuZ3RoLlxuICAgKiBAcGFyYW0gYiBUaGUgbmV3IGJvZHkgY29udGVudHMuXG4gICAqL1xuICBwdWJsaWMgc2V0UmVzcG9uc2VCb2R5KGI6IEJ1ZmZlcikge1xuICAgIHRoaXMuX3Jlc3BvbnNlQm9keSA9IGI7XG4gICAgLy8gVXBkYXRlIGNvbnRlbnQtbGVuZ3RoLlxuICAgIHRoaXMucmVzcG9uc2Uuc2V0SGVhZGVyKCdjb250ZW50LWxlbmd0aCcsIGAke2IubGVuZ3RofWApO1xuICAgIC8vIFRPRE86IENvbnRlbnQtZW5jb2Rpbmc/XG4gIH1cblxuICAvKipcbiAgICogUGFjayBpbnRvIGEgYnVmZmVyIGZvciB0cmFuc21pc3Npb24gdG8gTUlUTVByb3h5LlxuICAgKi9cbiAgcHVibGljIHRvQnVmZmVyKCk6IEJ1ZmZlciB7XG4gICAgY29uc3QgbWV0YWRhdGEgPSBCdWZmZXIuZnJvbShKU09OLnN0cmluZ2lmeSh0aGlzLnJlc3BvbnNlKSwgJ3V0ZjgnKTtcbiAgICBjb25zdCBtZXRhZGF0YUxlbmd0aCA9IG1ldGFkYXRhLmxlbmd0aDtcbiAgICBjb25zdCByZXNwb25zZUxlbmd0aCA9IHRoaXMuX3Jlc3BvbnNlQm9keS5sZW5ndGhcbiAgICBjb25zdCBydiA9IEJ1ZmZlci5hbGxvYyg4ICsgbWV0YWRhdGFMZW5ndGggKyByZXNwb25zZUxlbmd0aCk7XG4gICAgcnYud3JpdGVJbnQzMkxFKG1ldGFkYXRhTGVuZ3RoLCAwKTtcbiAgICBydi53cml0ZUludDMyTEUocmVzcG9uc2VMZW5ndGgsIDQpO1xuICAgIG1ldGFkYXRhLmNvcHkocnYsIDgpO1xuICAgIHRoaXMuX3Jlc3BvbnNlQm9keS5jb3B5KHJ2LCA4ICsgbWV0YWRhdGFMZW5ndGgpO1xuICAgIHJldHVybiBydjtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU3Rhc2hlZEl0ZW0ge1xuICBjb25zdHJ1Y3RvcihcbiAgICBwdWJsaWMgcmVhZG9ubHkgcmF3VXJsOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IG1pbWVUeXBlOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IGRhdGE6IEJ1ZmZlcikge31cblxuICBwdWJsaWMgZ2V0IHNob3J0TWltZVR5cGUoKTogc3RyaW5nIHtcbiAgICBsZXQgbWltZSA9IHRoaXMubWltZVR5cGUudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAobWltZS5pbmRleE9mKFwiO1wiKSAhPT0gLTEpIHtcbiAgICAgIG1pbWUgPSBtaW1lLnNsaWNlKDAsIG1pbWUuaW5kZXhPZihcIjtcIikpO1xuICAgIH1cbiAgICByZXR1cm4gbWltZTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgaXNIdG1sKCk6IGJvb2xlYW4ge1xuICAgIHJldHVybiB0aGlzLnNob3J0TWltZVR5cGUgPT09IFwidGV4dC9odG1sXCI7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGlzSmF2YVNjcmlwdCgpOiBib29sZWFuIHtcbiAgICBzd2l0Y2godGhpcy5zaG9ydE1pbWVUeXBlKSB7XG4gICAgICBjYXNlICd0ZXh0L2phdmFzY3JpcHQnOlxuICAgICAgY2FzZSAnYXBwbGljYXRpb24vamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICd0ZXh0L3gtamF2YXNjcmlwdCc6XG4gICAgICBjYXNlICdhcHBsaWNhdGlvbi94LWphdmFzY3JpcHQnOlxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cbn1cblxuLyoqXG4gKiBDbGFzcyB0aGF0IGxhdW5jaGVzIE1JVE0gcHJveHkgYW5kIHRhbGtzIHRvIGl0IHZpYSBXZWJTb2NrZXRzLlxuICovXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNSVRNUHJveHkge1xuICBwcml2YXRlIHN0YXRpYyBfYWN0aXZlUHJvY2Vzc2VzOiBDaGlsZFByb2Nlc3NbXSA9IFtdO1xuXG4gIHB1YmxpYyBzdGF0aWMgYXN5bmMgQ3JlYXRlKGNiOiBJbnRlcmNlcHRvciA9IG5vcEludGVyY2VwdG9yKTogUHJvbWlzZTxNSVRNUHJveHk+IHtcbiAgICAvLyBDb25zdHJ1Y3QgV2ViU29ja2V0IHNlcnZlciwgYW5kIHdhaXQgZm9yIGl0IHRvIGJlZ2luIGxpc3RlbmluZy5cbiAgICBjb25zdCB3c3MgPSBuZXcgV2ViU29ja2V0U2VydmVyKHsgcG9ydDogODc2NSB9KTtcbiAgICBjb25zdCBwcm94eUNvbm5lY3RlZCA9IG5ldyBQcm9taXNlPHZvaWQ+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHdzcy5vbmNlKCdjb25uZWN0aW9uJywgKCkgPT4ge1xuICAgICAgICByZXNvbHZlKCk7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgICBjb25zdCBtcCA9IG5ldyBNSVRNUHJveHkoY2IpO1xuICAgIC8vIFNldCB1cCBXU1MgY2FsbGJhY2tzIGJlZm9yZSBNSVRNUHJveHkgY29ubmVjdHMuXG4gICAgbXAuX2luaXRpYWxpemVXU1Mod3NzKTtcbiAgICBhd2FpdCBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB3c3Mub25jZSgnbGlzdGVuaW5nJywgKCkgPT4ge1xuICAgICAgICB3c3MucmVtb3ZlTGlzdGVuZXIoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgfSk7XG4gICAgICB3c3Mub25jZSgnZXJyb3InLCByZWplY3QpO1xuICAgIH0pO1xuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHdhaXRGb3JQb3J0KDgwODAsIDEpO1xuICAgICAgY29uc29sZS5sb2coYE1JVE1Qcm94eSBhbHJlYWR5IHJ1bm5pbmcuYCk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5sb2coYE1JVE1Qcm94eSBub3QgcnVubmluZzsgc3RhcnRpbmcgdXAgbWl0bXByb3h5LmApO1xuICAgICAgLy8gU3RhcnQgdXAgTUlUTSBwcm9jZXNzLlxuICAgICAgLy8gLS1hbnRpY2FjaGUgbWVhbnMgdG8gZGlzYWJsZSBjYWNoaW5nLCB3aGljaCBnZXRzIGluIHRoZSB3YXkgb2YgdHJhbnNwYXJlbnRseSByZXdyaXRpbmcgY29udGVudC5cbiAgICAgIGNvbnN0IG1pdG1Qcm9jZXNzID0gc3Bhd24oXCJtaXRtZHVtcFwiLCBbXCItLWFudGljYWNoZVwiLCBcIi1zXCIsIHJlc29sdmUoX19kaXJuYW1lLCBcIi4uL3NjcmlwdHMvcHJveHkucHlcIildLCB7XG4gICAgICAgIHN0ZGlvOiAnaW5oZXJpdCdcbiAgICAgIH0pO1xuICAgICAgaWYgKE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLnB1c2gobWl0bVByb2Nlc3MpID09PSAxKSB7XG4gICAgICAgIHByb2Nlc3Mub24oJ1NJR0lOVCcsIE1JVE1Qcm94eS5fY2xlYW51cCk7XG4gICAgICAgIHByb2Nlc3Mub24oJ2V4aXQnLCBNSVRNUHJveHkuX2NsZWFudXApO1xuICAgICAgfVxuICAgICAgbXAuX2luaXRpYWxpemVNSVRNUHJveHkobWl0bVByb2Nlc3MpO1xuICAgICAgLy8gV2FpdCBmb3IgcG9ydCA4MDgwIHRvIGNvbWUgb25saW5lLlxuICAgICAgYXdhaXQgd2FpdEZvclBvcnQoODA4MCk7XG4gICAgfVxuICAgIGF3YWl0IHByb3h5Q29ubmVjdGVkO1xuXG4gICAgcmV0dXJuIG1wO1xuICB9XG5cbiAgcHJpdmF0ZSBzdGF0aWMgX2NsZWFudXBDYWxsZWQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzdGF0aWMgX2NsZWFudXAoKTogdm9pZCB7XG4gICAgaWYgKE1JVE1Qcm94eS5fY2xlYW51cENhbGxlZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBNSVRNUHJveHkuX2NsZWFudXBDYWxsZWQgPSB0cnVlO1xuICAgIE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLmZvckVhY2goKHApID0+IHtcbiAgICAgIHAua2lsbCgnU0lHS0lMTCcpO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3Rhc2hFbmFibGVkOiBib29sZWFuID0gZmFsc2U7XG4gIC8vIFRvZ2dsZSB3aGV0aGVyIG9yIG5vdCBtaXRtcHJveHktbm9kZSBzdGFzaGVzIG1vZGlmaWVkIHNlcnZlciByZXNwb25zZXMuXG4gIC8vICoqTm90IHVzZWQgZm9yIHBlcmZvcm1hbmNlKiosIGJ1dCBlbmFibGVzIE5vZGUuanMgY29kZSB0byBmZXRjaCBwcmV2aW91cyBzZXJ2ZXIgcmVzcG9uc2VzIGZyb20gdGhlIHByb3h5LlxuICBwdWJsaWMgZ2V0IHN0YXNoRW5hYmxlZCgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gdGhpcy5fc3Rhc2hFbmFibGVkO1xuICB9XG4gIHB1YmxpYyBzZXQgc3Rhc2hFbmFibGVkKHY6IGJvb2xlYW4pIHtcbiAgICBpZiAoIXYpIHtcbiAgICAgIHRoaXMuX3N0YXNoLmNsZWFyKCk7XG4gICAgfVxuICAgIHRoaXMuX3N0YXNoRW5hYmxlZCA9IHY7XG4gIH1cbiAgcHJpdmF0ZSBfbWl0bVByb2Nlc3M6IENoaWxkUHJvY2VzcyA9IG51bGw7XG4gIHByaXZhdGUgX21pdG1FcnJvcjogRXJyb3IgPSBudWxsO1xuICBwcml2YXRlIF93c3M6IFdlYlNvY2tldFNlcnZlciA9IG51bGw7XG4gIHB1YmxpYyBjYjogSW50ZXJjZXB0b3I7XG4gIHByaXZhdGUgX3N0YXNoID0gbmV3IE1hcDxzdHJpbmcsIFN0YXNoZWRJdGVtPigpO1xuXG4gIHByaXZhdGUgY29uc3RydWN0b3IoY2I6IEludGVyY2VwdG9yKSB7XG4gICAgdGhpcy5jYiA9IGNiO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5pdGlhbGl6ZVdTUyh3c3M6IFdlYlNvY2tldFNlcnZlcik6IHZvaWQge1xuICAgIHRoaXMuX3dzcyA9IHdzcztcbiAgICB0aGlzLl93c3Mub24oJ2Nvbm5lY3Rpb24nLCAod3MpID0+IHtcbiAgICAgIHdzLm9uKCdtZXNzYWdlJywgKG1lc3NhZ2U6IEJ1ZmZlcikgPT4ge1xuICAgICAgICBjb25zdCBvcmlnaW5hbCA9IEludGVyY2VwdGVkSFRUUE1lc3NhZ2UuRnJvbUJ1ZmZlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jYihvcmlnaW5hbCk7XG4gICAgICAgIC8vIFJlbW92ZSB0cmFuc2Zlci1lbmNvZGluZy4gV2UgZG9uJ3Qgc3VwcG9ydCBjaHVua2VkLlxuICAgICAgICBpZiAodGhpcy5fc3Rhc2hFbmFibGVkKSB7XG4gICAgICAgICAgdGhpcy5fc3Rhc2guc2V0KG9yaWdpbmFsLnJlcXVlc3QucmF3VXJsLFxuICAgICAgICAgICAgbmV3IFN0YXNoZWRJdGVtKG9yaWdpbmFsLnJlcXVlc3QucmF3VXJsLCBvcmlnaW5hbC5yZXNwb25zZS5nZXRIZWFkZXIoJ2NvbnRlbnQtdHlwZScpLCBvcmlnaW5hbC5yZXNwb25zZUJvZHkpKTtcbiAgICAgICAgfVxuICAgICAgICB3cy5zZW5kKG9yaWdpbmFsLnRvQnVmZmVyKCkpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9pbml0aWFsaXplTUlUTVByb3h5KG1pdG1Qcm94eTogQ2hpbGRQcm9jZXNzKTogdm9pZCB7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3MgPSBtaXRtUHJveHk7XG4gICAgdGhpcy5fbWl0bVByb2Nlc3Mub24oJ2V4aXQnLCAoY29kZSwgc2lnbmFsKSA9PiB7XG4gICAgICBjb25zdCBpbmRleCA9IE1JVE1Qcm94eS5fYWN0aXZlUHJvY2Vzc2VzLmluZGV4T2YodGhpcy5fbWl0bVByb2Nlc3MpO1xuICAgICAgaWYgKGluZGV4ICE9PSAtMSkge1xuICAgICAgICBNSVRNUHJveHkuX2FjdGl2ZVByb2Nlc3Nlcy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgICAgfVxuICAgICAgaWYgKGNvZGUgIT09IG51bGwpIHtcbiAgICAgICAgaWYgKGNvZGUgIT09IDApIHtcbiAgICAgICAgICB0aGlzLl9taXRtRXJyb3IgPSBuZXcgRXJyb3IoYFByb2Nlc3MgZXhpdGVkIHdpdGggY29kZSAke2NvZGV9LmApO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9taXRtRXJyb3IgPSBuZXcgRXJyb3IoYFByb2Nlc3MgZXhpdGVkIGR1ZSB0byBzaWduYWwgJHtzaWduYWx9LmApO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHRoaXMuX21pdG1Qcm9jZXNzLm9uKCdlcnJvcicsIChlcnIpID0+IHtcbiAgICAgIHRoaXMuX21pdG1FcnJvciA9IGVycjtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZXMgdGhlIGdpdmVuIFVSTCBmcm9tIHRoZSBzdGFzaC5cbiAgICogQHBhcmFtIHVybFxuICAgKi9cbiAgcHVibGljIGdldEZyb21TdGFzaCh1cmw6IHN0cmluZyk6IFN0YXNoZWRJdGVtIHtcbiAgICByZXR1cm4gdGhpcy5fc3Rhc2guZ2V0KHVybCk7XG4gIH1cblxuICBwdWJsaWMgZm9yRWFjaFN0YXNoSXRlbShjYjogKHZhbHVlOiBTdGFzaGVkSXRlbSwgdXJsOiBzdHJpbmcpID0+IHZvaWQpOiB2b2lkIHtcbiAgICB0aGlzLl9zdGFzaC5mb3JFYWNoKGNiKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXF1ZXN0cyB0aGUgZ2l2ZW4gVVJMIGZyb20gdGhlIHByb3h5LlxuICAgKi9cbiAgcHVibGljIGFzeW5jIHByb3h5R2V0KHVybFN0cmluZzogc3RyaW5nKTogUHJvbWlzZTxIVFRQUmVzcG9uc2U+IHtcbiAgICBjb25zdCB1cmwgPSBwYXJzZVVSTCh1cmxTdHJpbmcpO1xuICAgIGNvbnN0IGdldCA9IHVybC5wcm90b2NvbCA9PT0gXCJodHRwOlwiID8gaHR0cEdldCA6IGh0dHBzR2V0O1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxIVFRQUmVzcG9uc2U+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IHJlcSA9IGdldCh7XG4gICAgICAgIHVybDogdXJsU3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgaG9zdDogdXJsLmhvc3RcbiAgICAgICAgfSxcbiAgICAgICAgaG9zdDogJ2xvY2FsaG9zdCcsXG4gICAgICAgIHBvcnQ6IDgwODAsXG4gICAgICAgIHBhdGg6IHVybFN0cmluZ1xuICAgICAgfSwgKHJlcykgPT4ge1xuICAgICAgICBjb25zdCBkYXRhID0gbmV3IEFycmF5PEJ1ZmZlcj4oKTtcbiAgICAgICAgcmVzLm9uKCdkYXRhJywgKGNodW5rOiBCdWZmZXIpID0+IHtcbiAgICAgICAgICBkYXRhLnB1c2goY2h1bmspO1xuICAgICAgICB9KTtcbiAgICAgICAgcmVzLm9uKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgICAgY29uc3QgZCA9IEJ1ZmZlci5jb25jYXQoZGF0YSk7XG4gICAgICAgICAgcmVzb2x2ZSh7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiByZXMuc3RhdHVzQ29kZSxcbiAgICAgICAgICAgIGhlYWRlcnM6IHJlcy5oZWFkZXJzLFxuICAgICAgICAgICAgYm9keTogZFxuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgICAgcmVzLm9uY2UoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICAgIH0pO1xuICAgICAgcmVxLm9uY2UoJ2Vycm9yJywgcmVqZWN0KTtcbiAgICB9KTtcbiAgfVxuXG4gIHB1YmxpYyBhc3luYyBzaHV0ZG93bigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgY29uc3QgY2xvc2VXU1MgPSAoKSA9PiB7XG4gICAgICAgIHRoaXMuX3dzcy5jbG9zZSgoZXJyKSA9PiB7XG4gICAgICAgICAgaWYgKGVycikge1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfTtcblxuICAgICAgaWYgKHRoaXMuX21pdG1Qcm9jZXNzICYmIHRoaXMuX21pdG1Qcm9jZXNzLmNvbm5lY3RlZCkge1xuICAgICAgICB0aGlzLl9taXRtUHJvY2Vzcy5vbmNlKCdleGl0JywgKGNvZGUsIHNpZ25hbCkgPT4ge1xuICAgICAgICAgIGNsb3NlV1NTKCk7XG4gICAgICAgIH0pO1xuICAgICAgICB0aGlzLl9taXRtUHJvY2Vzcy5raWxsKCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjbG9zZVdTUygpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59XG4iXX0=