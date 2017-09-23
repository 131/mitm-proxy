'use strict';

var zlib = require('zlib');

module.exports = function(ctx) {

  ctx.on('onRequest', function(ctx) {
    ctx.proxyToServerRequestOptions.headers['accept-encoding'] = 'gzip';
  });

  ctx.on('onResponse', function(ctx) {
    var encoding = (ctx.remote_res.headers['content-encoding'] || '').toLowerCase();

    if(encoding == 'gzip') {
      delete ctx.remote_res.headers['content-encoding'];
      ctx.addResponseFilter(zlib.createGunzip());
    }
  });

};

