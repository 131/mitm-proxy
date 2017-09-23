"use strict";

const Events = require('events').EventEmitter;

class FinalResponseFilter extends Events {

  constructor(proxy, ctx) {
    super();
    this.writable = true;

      //make sure proper binding
    this.write = this.write.bind(this, proxy, ctx);
    this.end = this.end.bind(this, proxy, ctx);
  }

  write(proxy, ctx, chunk) {
    proxy._onResponseData(ctx, chunk).then(function(chunk) {
      if (chunk)
        ctx.res.write(chunk);
    }).catch(function(err) {
      proxy._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
    });
    return true;
  }

  async end(proxy, ctx, chunk) {
    if (chunk) {
      try {
        chunk = await proxy._onResponseData(ctx, chunk);
      } catch(err) {
        return proxy._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
      }
    }

    try {
      await this.emit('onResponseEnd', ctx);
      await ctx.emit('onResponseEnd', ctx);
    } catch(err) {
      return proxy._onError('ON_RESPONSE_END_ERROR', ctx, err);
    }

    return ctx.res.end(chunk || undefined);
  }
}

module.exports = FinalResponseFilter;
