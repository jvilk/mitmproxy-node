# mitmproxy-node 2.1.1

A bridge between Python's [`mitmproxy`](https://mitmproxy.org/) and Node.JS programs. Rewrite network requests using Node.JS!

## Why?

It is far easier to rewrite JavaScript/HTML/etc using JavaScript than Python, but mitmproxy only accepts Python plugins.
There are no decent alternatives to mitmproxy, so this package lets me use mitmproxy with Node.js-based rewriting code.

## What can I use this for?

For transparently rewriting HTTP/HTTPS responses. The mitmproxy plugin lets every HTTP request go through to the server uninhibited, and then passes it to Node.js via a WebSocket for rewriting. You can optionally specify a list of paths that should be directly intercepted without being passed to the server.

If you want to add additional functionality, such as filtering or whatnot, I'll accept pull requests so long as they do not noticeably hinder performance.

## How does it work?

A Python plugin for `mitmproxy` starts a WebSocket server, and `mitmproxy-node` talks with it over WebSocket messages. The two communicate via binary messages to reduce marshaling-related overhead.

## Your Python plugin is bad and you should feel bad

I have no idea what I am doing. PRs to improve my Python code are appreciated!

## Pre-requisites

* [`mitmproxy` V4](https://mitmproxy.org/) must be installed and runnable from the terminal. The install method cannot be a prebuilt binary or homebrew, since those packages are missing the Python websockets module. Install via `pip` or from source.
* Python 3.6, since I use the new async/await syntax in the mitmproxy plugin
* `npm install` to pull in Node and PIP dependencies.

## Using

You can either start `mitmproxy` manually with `mitmdump --anticache -s scripts/proxy.py`, or `mitmproxy-node` will do so automatically for you.
`mitmproxy-node` auto-detects if `mitmproxy` is already running.
If you frequently start/stop the proxy, it may be best to start it manually.

```javascript
import MITMProxy from 'mitmproxy-node';

// Returns Promise<MITMProxy>
async function makeProxy() {
  // Note: Your interceptor can also be asynchronous and return a Promise!
  return MITMProxy.Create(function(interceptedMsg) {
    const req = interceptedMsg.request;
    const res = interceptedMsg.response;
    if (req.rawUrl.contains("target.js") && res.getHeader('content-type').indexOf("javascript") !== -1) {
      interceptedMsg.setResponseBody(Buffer.from(`Hacked!`, 'utf8'));
    }
  }, ['/eval'] /* list of paths to directly intercept -- don't send to server */,
  true /* Be quiet; turn off for debug messages */,
  true /* Only intercept text or potentially-text requests (all mime types with *application* and *text* in them, plus responses with no mime type) */
  );
}

async function main() {
  const proxy = await makeProxy();
  // when done:
  await proxy.shutdown();
}
```

Without fancy async/await:

```javascript
import MITMProxy from 'mitmproxy-node';

// Returns Promise<MITMProxy>
function makeProxy() {
  return MITMProxy.Create(function(interceptedMsg) {
    const req = interceptedMsg.request;
    const res = interceptedMsg.response;
    if (req.rawUrl.contains("target.js") && res.getHeader('content-type').indexOf("javascript") !== -1) {
      interceptedMsg.setResponseBody(Buffer.from(`Hacked!`, 'utf8'));
    }
  }, ['/eval'], true, true);
}

function main() {
  makeProxy().then((proxy) => {
    // when done
    proxy.shutdown.then(() => {
      // Proxy is closed!
    });
  });
}
```

## Building

`npm run build`
