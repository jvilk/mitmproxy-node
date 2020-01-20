/// <reference types="node" />
import { Url } from 'url';
/**
 * Function that intercepts and rewrites HTTP responses.
 */
export declare type Interceptor = (m: InterceptedHTTPMessage) => void | Promise<void>;
/**
 * An interceptor that does nothing.
 */
export declare function nopInterceptor(m: InterceptedHTTPMessage): void;
/**
 * The core HTTP response.
 */
export interface HTTPResponse {
    statusCode: number;
    headers: {
        [name: string]: string;
    };
    body: Buffer;
}
/**
 * Metadata associated with an HTTP request.
 */
export interface HTTPRequestMetadata {
    method: string;
    url: string;
    headers: [string, string][];
}
/**
 * Metadata associated with an HTTP response.
 */
export interface HTTPResponseMetadata {
    status_code: number;
    headers: [string, string][];
}
/**
 * Abstract class that represents HTTP headers.
 */
export declare abstract class AbstractHTTPHeaders {
    private _headers;
    readonly headers: [string, string][];
    constructor(headers: [string, string][]);
    private _indexOfHeader(name);
    /**
     * Get the value of the given header field.
     * If there are multiple fields with that name, this only returns the first field's value!
     * @param name Name of the header field
     */
    getHeader(name: string): string;
    /**
     * Set the value of the given header field. Assumes that there is only one field with the given name.
     * If the field does not exist, it adds a new field with the name and value.
     * @param name Name of the field.
     * @param value New value.
     */
    setHeader(name: string, value: string): void;
    /**
     * Removes the header field with the given name. Assumes that there is only one field with the given name.
     * Does nothing if field does not exist.
     * @param name Name of the field.
     */
    removeHeader(name: string): void;
    /**
     * Removes all header fields.
     */
    clearHeaders(): void;
}
/**
 * Represents a MITM-ed HTTP response from a server.
 */
export declare class InterceptedHTTPResponse extends AbstractHTTPHeaders {
    statusCode: number;
    constructor(metadata: HTTPResponseMetadata);
    toJSON(): HTTPResponseMetadata;
}
/**
 * Represents an intercepted HTTP request from a client.
 */
export declare class InterceptedHTTPRequest extends AbstractHTTPHeaders {
    method: string;
    rawUrl: string;
    url: Url;
    constructor(metadata: HTTPRequestMetadata);
}
/**
 * Represents an intercepted HTTP request/response pair.
 */
export declare class InterceptedHTTPMessage {
    /**
     * Unpack from a Buffer received from MITMProxy.
     * @param b
     */
    static FromBuffer(b: Buffer): InterceptedHTTPMessage;
    readonly request: InterceptedHTTPRequest;
    readonly response: InterceptedHTTPResponse;
    readonly requestBody: Buffer;
    readonly responseBody: Buffer;
    private _responseBody;
    private constructor();
    /**
     * Changes the body of the HTTP response. Appropriately updates content-length.
     * @param b The new body contents.
     */
    setResponseBody(b: Buffer): void;
    /**
     * Changes the status code of the HTTP response.
     * @param code The new status code.
     */
    setStatusCode(code: number): void;
    /**
     * Pack into a buffer for transmission to MITMProxy.
     */
    toBuffer(): Buffer;
}
export declare class StashedItem {
    readonly rawUrl: string;
    readonly mimeType: string;
    readonly data: Buffer;
    constructor(rawUrl: string, mimeType: string, data: Buffer);
    readonly shortMimeType: string;
    readonly isHtml: boolean;
    readonly isJavaScript: boolean;
}
/**
 * Class that launches MITM proxy and talks to it via WebSockets.
 */
export default class MITMProxy {
    private static _activeProcesses;
    /**
     * Creates a new MITMProxy instance.
     * @param cb Called with intercepted HTTP requests / responses.
     * @param interceptPaths List of paths to completely intercept without sending to the server (e.g. ['/eval'])
     * @param quiet If true, do not print debugging messages (defaults to 'true').
     * @param onlyInterceptTextFiles If true, only intercept text files (JavaScript/HTML/CSS/etc, and ignore media files).
     */
    static Create(cb?: Interceptor, interceptPaths?: string[], quiet?: boolean, onlyInterceptTextFiles?: boolean, ignoreHosts?: string | null): Promise<MITMProxy>;
    private static _cleanupCalled;
    private static _cleanup();
    private _stashEnabled;
    stashEnabled: boolean;
    private _mitmProcess;
    private _mitmError;
    private _wss;
    cb: Interceptor;
    readonly onlyInterceptTextFiles: boolean;
    private _stash;
    private _stashFilter;
    stashFilter: (url: string, item: StashedItem) => boolean;
    private constructor();
    private _initializeWSS(wss);
    private _initializeMITMProxy(mitmProxy);
    /**
     * Retrieves the given URL from the stash.
     * @param url
     */
    getFromStash(url: string): StashedItem;
    forEachStashItem(cb: (value: StashedItem, url: string) => void): void;
    /**
     * Requests the given URL from the proxy.
     */
    proxyGet(urlString: string): Promise<HTTPResponse>;
    shutdown(): Promise<void>;
}
