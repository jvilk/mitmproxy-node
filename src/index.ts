import {Server as WebSocketServer} from 'ws';
import {spawn, ChildProcess} from 'child_process';
import {resolve} from 'path';
import {parse as parseURL, Url} from 'url';
import {get as httpGet} from 'http';
import {get as httpsGet} from 'https';
import {createConnection, Socket} from 'net';

/**
 * Wait for the specified port to open.
 * @param port The port to watch for.
 * @param retries The number of times to retry before giving up. Defaults to 10.
 * @param interval The interval between retries, in milliseconds. Defaults to 500.
 */
function waitForPort(port: number, retries: number = 10, interval: number = 500): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let retriesRemaining = retries;
    let retryInterval = interval;
    let timer: NodeJS.Timer = null;
    let socket: Socket = null;

    function clearTimerAndDestroySocket() {
      clearTimeout(timer);
      timer = null;
      if (socket) socket.destroy();
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

      socket = createConnection(port, "localhost", function() {
        clearTimerAndDestroySocket();
        if (retriesRemaining >= 0) resolve();
      });

      timer = setTimeout(function() { retry(); }, retryInterval);

      socket.on('error', function(err) {
        clearTimerAndDestroySocket();
        setTimeout(retry, retryInterval);
      });
    }

    tryToConnect();
  });
}

/**
 * Function that intercepts and rewrites HTTP responses.
 */
export type Interceptor = (m: InterceptedHTTPMessage) => void | Promise<void>;

/**
 * An interceptor that does nothing.
 */
export function nopInterceptor(m: InterceptedHTTPMessage): void {}

/**
 * The core HTTP response.
 */
export interface HTTPResponse {
  statusCode: number,
  headers: {[name: string]: string};
  body: Buffer;
}

/**
 * Metadata associated with a request/response pair.
 */
interface HTTPMessageMetadata {
  request: HTTPRequestMetadata;
  response: HTTPResponseMetadata;
}

/**
 * Metadata associated with an HTTP request.
 */
export interface HTTPRequestMetadata {
  // GET, DELETE, POST,  etc.
  method: string;
  // Target URL for the request.
  url: string;
  // The set of headers from the request, as key-value pairs.
  // Since header fields may be repeated, this array may contain multiple entries for the same key.
  headers: [string, string][];
}

/**
 * Metadata associated with an HTTP response.
 */
export interface HTTPResponseMetadata {
  // The numerical status code.
  status_code: number;
  // The set of headers from the response, as key-value pairs.
  // Since header fields may be repeated, this array may contain multiple entries for the same key.
  headers: [string, string][];
}

/**
 * Abstract class that represents HTTP headers.
 */
export abstract class AbstractHTTPHeaders {
  private _headers: [string, string][];
  // The raw headers, as a sequence of key/value pairs.
  // Since header fields may be repeated, this array may contain multiple entries for the same key.
  public get headers(): [string, string][] {
    return this._headers;
  }
  constructor(headers: [string, string][]) {
    this._headers = headers;
  }

  private _indexOfHeader(name: string): number {
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
  public getHeader(name: string): string {
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
  public setHeader(name: string, value: string): void {
    const index = this._indexOfHeader(name.toLowerCase());
    if (index !== -1) {
      this.headers[index][1] = value;
    } else {
      this.headers.push([name, value]);
    }
  }

  /**
   * Removes the header field with the given name. Assumes that there is only one field with the given name.
   * Does nothing if field does not exist.
   * @param name Name of the field.
   */
  public removeHeader(name: string): void {
    const index = this._indexOfHeader(name.toLowerCase());
    if (index !== -1) {
      this.headers.splice(index, 1);
    }
  }

  /**
   * Removes all header fields.
   */
  public clearHeaders(): void {
    this._headers = [];
  }
}

/**
 * Represents a MITM-ed HTTP response from a server.
 */
export class InterceptedHTTPResponse extends AbstractHTTPHeaders {
  // The status code of the HTTP response.
  public statusCode: number;

  constructor(metadata: HTTPResponseMetadata) {
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

  public toJSON(): HTTPResponseMetadata {
    return {
      status_code: this.statusCode,
      headers: this.headers
    };
  }
}

/**
 * Represents an intercepted HTTP request from a client.
 */
export class InterceptedHTTPRequest extends AbstractHTTPHeaders {
  // HTTP method (GET/DELETE/etc)
  public method: string;
  // The URL as a string.
  public rawUrl: string;
  // The URL as a URL object.
  public url: Url;

  constructor(metadata: HTTPRequestMetadata) {
    super(metadata.headers);
    this.method = metadata.method.toLowerCase();
    this.rawUrl = metadata.url;
    this.url = parseURL(this.rawUrl);
  }
}

/**
 * Represents an intercepted HTTP request/response pair.
 */
export class InterceptedHTTPMessage {
  /**
   * Unpack from a Buffer received from MITMProxy.
   * @param b
   */
  public static FromBuffer(b: Buffer): InterceptedHTTPMessage {
    const metadataSize = b.readInt32LE(0);
    const requestSize = b.readInt32LE(4);
    const responseSize = b.readInt32LE(8);
    const metadata: HTTPMessageMetadata = JSON.parse(b.toString("utf8", 12, 12 + metadataSize));
    return new InterceptedHTTPMessage(
      new InterceptedHTTPRequest(metadata.request),
      new InterceptedHTTPResponse(metadata.response),
      b.slice(12 + metadataSize, 12 + metadataSize + requestSize),
      b.slice(12 + metadataSize + requestSize, 12 + metadataSize + requestSize + responseSize)
    );
  }

  public readonly request: InterceptedHTTPRequest;
  public readonly response: InterceptedHTTPResponse;
  // The body of the HTTP request.
  public readonly requestBody: Buffer;
  // The body of the HTTP response. Read-only; change the response body via setResponseBody.
  public get responseBody(): Buffer {
    return this._responseBody;
  }
  private _responseBody: Buffer;
  private constructor(request: InterceptedHTTPRequest, response: InterceptedHTTPResponse, requestBody: Buffer, responseBody: Buffer) {
    this.request = request;
    this.response = response;
    this.requestBody = requestBody;
    this._responseBody = responseBody;
  }

  /**
   * Changes the body of the HTTP response. Appropriately updates content-length.
   * @param b The new body contents.
   */
  public setResponseBody(b: Buffer) {
    this._responseBody = b;
    // Update content-length.
    this.response.setHeader('content-length', `${b.length}`);
    // TODO: Content-encoding?
  }
  
  /**
   * Changes the status code of the HTTP response.
   * @param code The new status code.
   */
  public setStatusCode(code: number) {
    this.response.statusCode = code;
  }

  /**
   * Pack into a buffer for transmission to MITMProxy.
   */
  public toBuffer(): Buffer {
    const metadata = Buffer.from(JSON.stringify(this.response), 'utf8');
    const metadataLength = metadata.length;
    const responseLength = this._responseBody.length
    const rv = Buffer.alloc(8 + metadataLength + responseLength);
    rv.writeInt32LE(metadataLength, 0);
    rv.writeInt32LE(responseLength, 4);
    metadata.copy(rv, 8);
    this._responseBody.copy(rv, 8 + metadataLength);
    return rv;
  }
}

export class StashedItem {
  constructor(
    public readonly rawUrl: string,
    public readonly mimeType: string,
    public readonly data: Buffer) {}

  public get shortMimeType(): string {
    let mime = this.mimeType.toLowerCase();
    if (mime.indexOf(";") !== -1) {
      mime = mime.slice(0, mime.indexOf(";"));
    }
    return mime;
  }

  public get isHtml(): boolean {
    return this.shortMimeType === "text/html";
  }

  public get isJavaScript(): boolean {
    switch(this.shortMimeType) {
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

function defaultStashFilter(url: string, item: StashedItem): boolean {
  return item.isJavaScript || item.isHtml;
}

/**
 * Class that launches MITM proxy and talks to it via WebSockets.
 */
export default class MITMProxy {
  private static _activeProcesses: ChildProcess[] = [];

  /**
   * Creates a new MITMProxy instance.
   * @param cb Called with intercepted HTTP requests / responses.
   * @param interceptPaths List of paths to completely intercept without sending to the server (e.g. ['/eval'])
   * @param quiet If true, do not print debugging messages (defaults to 'true').
   * @param onlyInterceptTextFiles If true, only intercept text files (JavaScript/HTML/CSS/etc, and ignore media files).
   */
  public static async Create(cb: Interceptor = nopInterceptor, interceptPaths: string[] = [], quiet: boolean = true, onlyInterceptTextFiles = false, ignoreHosts: string | null = null): Promise<MITMProxy> {
    // Construct WebSocket server, and wait for it to begin listening.
    const wss = new WebSocketServer({ port: 8765 });
    const proxyConnected = new Promise<void>((resolve, reject) => {
      wss.once('connection', () => {
        resolve();
      });
    });
    const mp = new MITMProxy(cb, onlyInterceptTextFiles);
    // Set up WSS callbacks before MITMProxy connects.
    mp._initializeWSS(wss);
    await new Promise<void>((resolve, reject) => {
      wss.once('listening', () => {
        wss.removeListener('error', reject);
        resolve();
      });
      wss.once('error', reject);
    });

    try {
      try {
        await waitForPort(8080, 1);
        if (!quiet) {
          console.log(`MITMProxy already running.`);
        }
      } catch (e) {
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

        const options = ["--anticache", "-s", resolve(__dirname, `../scripts/proxy.py`)].concat(scriptArgs);
        if (quiet) {
          options.push('-q');
        }
        
        // allow self-signed SSL certificates
        options.push("--ssl-insecure");
        
        const mitmProcess = spawn("mitmdump", options, {
          stdio: 'inherit'
        });
        const mitmProxyExited = new Promise<void>((_, reject) => {
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
          await Promise.race([mitmProxyExited, waitingForPort]);
        } catch (e) {
          if (e && typeof(e) === 'object' && e.code === "ENOENT") {
            throw new Error(`mitmdump, which is an executable that ships with mitmproxy, is not on your PATH. Please ensure that you can run mitmdump --version successfully from your command line.`)
          } else {
            throw new Error(`Unable to start mitmproxy: ${e}`);
          }
        }
      }
      await proxyConnected;
    } catch (e) {
      await new Promise<any>((resolve) => wss.close(resolve));
      throw e;
    }

    return mp;
  }

  private static _cleanupCalled = false;
  private static _cleanup(): void {
    if (MITMProxy._cleanupCalled) {
      return;
    }
    MITMProxy._cleanupCalled = true;
    MITMProxy._activeProcesses.forEach((p) => {
      p.kill('SIGKILL');
    });
  }

  private _stashEnabled: boolean = false;
  // Toggle whether or not mitmproxy-node stashes modified server responses.
  // **Not used for performance**, but enables Node.js code to fetch previous server responses from the proxy.
  public get stashEnabled(): boolean {
    return this._stashEnabled;
  }
  public set stashEnabled(v: boolean) {
    if (!v) {
      this._stash.clear();
    }
    this._stashEnabled = v;
  }
  private _mitmProcess: ChildProcess = null;
  private _mitmError: Error = null;
  private _wss: WebSocketServer = null;
  public cb: Interceptor;
  public readonly onlyInterceptTextFiles: boolean;
  private _stash = new Map<string, StashedItem>();
  private _stashFilter: (url: string, item: StashedItem) => boolean = defaultStashFilter;
  public get stashFilter(): (url: string, item: StashedItem) => boolean {
    return this._stashFilter;
  }
  public set stashFilter(value: (url: string, item: StashedItem) => boolean) {
    if (typeof(value) === 'function') {
      this._stashFilter = value;
    } else if (value === null) {
      this._stashFilter = defaultStashFilter;
    } else {
      throw new Error(`Invalid stash filter: Expected a function.`);
    }
  }

  private constructor(cb: Interceptor, onlyInterceptTextFiles: boolean) {
    this.cb = cb;
    this.onlyInterceptTextFiles = onlyInterceptTextFiles;
  }

  private _initializeWSS(wss: WebSocketServer): void {
    this._wss = wss;
    this._wss.on('connection', (ws) => {
      ws.on('error', (e) => {
        if ((e as any).code !== "ECONNRESET") {
          console.log(`WebSocket error: ${e}`);
        }
      });
      ws.on('message', async (message: Buffer) => {
        const original = InterceptedHTTPMessage.FromBuffer(message);
        const rv = this.cb(original);
        if (rv && typeof(rv) === 'object' && rv.then) {
          await rv;
        }
        // Remove transfer-encoding. We don't support chunked.
        if (this._stashEnabled) {
          const item = new StashedItem(original.request.rawUrl, original.response.getHeader('content-type'), original.responseBody);
          if (this._stashFilter(original.request.rawUrl, item)) {
            this._stash.set(original.request.rawUrl, item);
          }
        }
        ws.send(original.toBuffer());
      });
    });
  }

  private _initializeMITMProxy(mitmProxy: ChildProcess): void {
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
      } else {
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
  public getFromStash(url: string): StashedItem {
    return this._stash.get(url);
  }

  public forEachStashItem(cb: (value: StashedItem, url: string) => void): void {
    this._stash.forEach(cb);
  }

  /**
   * Requests the given URL from the proxy.
   */
  public async proxyGet(urlString: string): Promise<HTTPResponse> {
    const url = parseURL(urlString);
    const get = url.protocol === "http:" ? httpGet : httpsGet;
    return new Promise<HTTPResponse>((resolve, reject) => {
      const req = get({
        url: urlString,
        headers: {
          host: url.host
        },
        host: 'localhost',
        port: 8080,
        path: urlString
      }, (res) => {
        const data = new Array<Buffer>();
        res.on('data', (chunk: Buffer) => {
          data.push(chunk);
        });
        res.on('end', () => {
          const d = Buffer.concat(data);
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: d
          } as HTTPResponse);
        });
        res.once('error', reject);
      });
      req.once('error', reject);
    });
  }

  public async shutdown(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const closeWSS = () => {
        this._wss.close((err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      };

      if (this._mitmProcess && !this._mitmProcess.killed) {
        this._mitmProcess.once('exit', (code, signal) => {
          closeWSS();
        });
        this._mitmProcess.kill('SIGTERM');
      } else {
        closeWSS();
      }
    });
  }
}
