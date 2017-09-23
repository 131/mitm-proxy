"use strict";

const CA    = require('mitm-ca');
const Proxy = require('.');
const gunzip = require('./middleware/gunzip');


const path = require('path');
const caPath = path.resolve(process.cwd(), '.trashmeca');
const ca = new CA(caPath);

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
