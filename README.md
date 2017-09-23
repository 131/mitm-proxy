# mitm-proxy
An ES7 (async/await) supported version of [node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy).

# CA
Move all ca related stuffs to a dedicated [mitm-ca](https://github.com/131/mitm-ca) module.
Drop sni/wildcard support (for now). Proxy constructor now need a CA instance.

# WS
Remove all WS related features (for now)

# Plugins
Replace .use with async event flow.

# Logs & traces
Use [debug](https://github.com/tj/debug) for traces. Start proxy with DEBUG=* to view all traces.


# APIs

```
"use strict";

const CA    = require('mitm-ca');
const ca    = new CA('.trashmeca');

const Proxy = require('mitm-http');
const gunzip = require('mitm-http/middleware/gunzip');

const proxy = new Proxy(ca);



proxy.onError(function(ctx, err) {
  console.error('proxy error:', err);
});

proxy.on('onRequest', async function(ctx) {
  if (ctx.req.headers.host.indexOf('.google.') !== -1) {
    gunzip(ctx);
    ctx.onResponseData(function(ctx, chunk) {
      chunk = new Buffer(chunk.toString().replace(/<h3.*?<\/h3>/g, '<h3>Pwned!</h3>'));
      return chunk;
    });
  }
});

proxy.listen({port: 8080}, function(){
  console.log("Now listening");
});
```