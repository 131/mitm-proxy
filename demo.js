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