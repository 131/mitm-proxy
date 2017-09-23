"use strict";

const Events = require('events').EventEmitter;

class FinalRequestFilter extends Events {
  constructor(proxy, ctx) {
    super();
    this.writable = true;
    this.write = this.write.bind(this, proxy, ctx);
    this.end = this.end.bind(this, proxy, ctx);
  }

  async write(proxy, ctx, chunk) {
    proxy._onRequestData(ctx, chunk).then(function(chunk) {
     if (chunk)
        ctx.proxyToServerRequest.write(chunk);
    }).catch(function(err){
      proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err);
    });
    return true;
  }

  async end(proxy, ctx, chunk) {
    if (chunk) {
      try {
        chunk = await proxy._onRequestData(ctx, chunk);
      } catch(err) {
        return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err);
      }
    }

    try {
      await this.emit('onRequestEnd', ctx);
      await ctx.emit('onRequestEnd', ctx);
    } catch(err) {
      return this._onError('ON_REQUEST_END_ERROR', ctx, err);
    }
    return ctx.proxyToServerRequest.end(chunk || undefined);
  }
}

module.exports = FinalRequestFilter;