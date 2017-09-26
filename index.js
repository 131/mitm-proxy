'use strict';

const net = require('net');
const http = require('http');
const https = require('https');
const util = require('util');
const url = require('url');

const EventsAsync = require('eventemitter-async');
const sprintf = util.format;
const trace   = require('debug')('mitm');
const randInt = require('mout/random/randInt');

const FinalRequestFilter  = require('./filters/finalRequest');
const FinalResponseFilter = require('./filters/finalResponse');

class Proxy extends EventsAsync {

  constructor(ca){
    super();
    this.ca = ca;
    this.onErrorHandlers = [];
    this.onRequestDataHandlers = [];
    this.onResponseDataHandlers = [];

    this.sslServers = {};
  }

  onError (fn)   { this.onErrorHandlers.push(fn); return this; };
  onRequestData (fn) { this.onRequestDataHandlers.push(fn); return this; };
  onResponseData (fn) { this.onResponseDataHandlers.push(fn); return this; };


  async listen(options, callback) {
    this.httpPort = options.port || 8080;
    this.httpHost = options.host;
    this.timeout = options.timeout || 0;

    this.httpServer = http.createServer();
    this.httpServer.timeout = this.timeout;
    this.httpServer.on('error', this._onError.bind(this, 'HTTP_SERVER_ERROR', null));
    this.httpServer.on('connect', this._onHttpServerConnect.bind(this));
    this.httpServer.on('request', this._onHttpServerRequest.bind(this, false));
    const listenOptions = {
      host: this.httpHost,
      port: this.httpPort
    };

    this.httpServer.listen(listenOptions, callback);
  }


  close() {
    this.httpServer.close();
    delete this.httpServer;
    for(var srvName in this.sslServers) {
      var server = this.sslServers[srvName].server;
      if (server) server.close();
      delete this.sslServers[srvName];
    };
  }


  mitm(hostname, remote_addr, ports) {
    if(!ports) ports = [80, 443];
    var sslServer = await this._pickHTTPSserver(hostname);
    var addr = [127, randInt(0, 255), randInt(0, 255), randInt(0, 255)];

    for(var port of ports)
      sslServer.server.listen(port, addr);

    this.on('onRequestHeaders', function(ctx){
      if(ctx.proxyToServerRequestOptions.host == hostname)
        Object.assign(ctx.proxyToServerRequestOptions, { host: remote_addr });
    });

    return addr;
  }



  async _onHttpServerConnect(req, socket, head) {

    try {
      await this.emit('onConnect', req, socket, head);
    } catch(err) {
      return this._onError('ON_CONNECT_ERROR', null, err);
    }
    // we need first byte of data to detect if request is SSL encrypted
    if (!head || head.length === 0) {
      head = await new Promise(function(resolve){
        socket.once('data', resolve);
        socket.write('HTTP/1.1 200 OK\r\n');
        socket.write('\r\n');
      });
    }

    socket.pause();

    /*
    * Detect TLS from first bytes of data
    * Inspired from https://gist.github.com/tg-x/835636
    * used heuristic:
    * - an incoming connection using SSLv3/TLSv1 records should start with 0x16
    * - an incoming connection using SSLv2 records should start with the record size
    *   and as the first record should not be very big we can expect 0x80 or 0x00 (the MSB is a flag)
    * - everything else is considered to be unencrypted
    */

    var port = this.httpPort;

    if (head[0] == 0x16 || head[0] == 0x80 || head[0] == 0x00) {
      // URL is in the form 'hostname:port'
      var hostname = req.url.split(':', 2)[0];

      try {
        var sslServer = await this._pickHTTPSserver(hostname);
        port = sslServer.port;
      } catch(err) {
        return this._onError('OPEN_HTTPS_SERVER_ERROR', null, err);
      }
      
    }

    // open a TCP connection to the remote host
    var conn = net.connect(port, function() {
      // create a tunnel between the two hosts
      socket.pipe(conn);
      conn.pipe(socket);
      socket.emit('data', head);
      return socket.resume();
    });
    conn.on('error', this._onError.bind(this, 'PROXY_TO_PROXY_SOCKET_ERROR', null));
  }

  async _pickHTTPSserver(hostname) {
    var sslServer = this.sslServers[hostname];
    if(sslServer)
      return sslServer;

    var ctx = await this.ca.getBundle(hostname);

    trace('starting server for ', hostname);

    var server = https.createServer(ctx);
    server.timeout = this.timeout;
    server.on('error', this._onError.bind(this, 'HTTPS_SERVER_ERROR', null));
    server.on('clientError', this._onError.bind(this, 'HTTPS_CLIENT_ERROR', null));
    server.on('connect', this._onHttpServerConnect.bind(this)); //CONNECT
    server.on('request', this._onHttpServerRequest.bind(this, true));

    await new Promise(function(resolve) { server.listen(resolve); });

    var port = server.address().port;
    trace('https server started for %s on %s', hostname, port);
    this.sslServers[hostname] = {server,  port};
    return this.sslServers[hostname];
  }


  _onError(kind, ctx, err) {

    this.onErrorHandlers.forEach( fn => fn(ctx, err, kind));

    if (!ctx)
      return;

    ctx.onErrorHandlers.forEach(fn => fn(ctx, err, kind));

    if (ctx.res && !ctx.res.headersSent)
      ctx.res.writeHead(504, 'Proxy Error');

    if (ctx.res && !ctx.res.finished)
      ctx.res.end(sprintf("%s: %s", kind, err), 'utf8');
  }

  async _onHttpServerRequest (isSSL, req, res) {

    var ctx = Object.assign(new EventsAsync(), {
      isSSL,
      req,
      res,

      onErrorHandlers: [],
      onRequestDataHandlers: [],
      onResponseDataHandlers: [],
      requestFilters: [],
      responseFilters: [],
      onError: function(fn) {
        ctx.onErrorHandlers.push(fn);
        return ctx;
      },
      onRequestData: function(fn) {
        ctx.onRequestDataHandlers.push(fn);
        return ctx;
      },
      addRequestFilter: function(filter) {
        ctx.requestFilters.push(filter);
        return ctx;
      },
      onResponseData: function(fn) {
        ctx.onResponseDataHandlers.push(fn);
        return ctx;
      },
      addResponseFilter: function(filter) {
        ctx.responseFilters.push(filter);
        return ctx;
      }
    });

    req.on('error', this._onError.bind(this, 'CLIENT_TO_PROXY_REQUEST_ERROR', ctx));
    res.on('error', this._onError.bind(this, 'PROXY_TO_CLIENT_RESPONSE_ERROR', ctx));
    req.pause();

    var hostPort = Proxy.parseHostAndPort(req, ctx.isSSL ? 443 : 80);

    var headers = {};
    for (var h in req.headers) {
      // don't forward proxy- headers
      if (!/^proxy\-/i.test(h)) {
        headers[h] = req.headers[h];
      }
    }
    delete headers['content-length'];

    ctx.proxyToServerRequestOptions = {
      method: req.method,
      path: req.url,
      host: hostPort.host,
      port: hostPort.port,
      headers,
    };

    try {
      await this.emit('onRequest', ctx);
      await ctx.emit('onRequest', ctx);
    } catch(err){
      return this._onError('ON_REQUEST_ERROR', ctx, err);
    }
    try {
      await this.emit('onRequestHeaders', ctx);
    } catch(err) {
      return this._onError('ON_REQUESTHEADERS_ERROR', ctx, err);
    }

    var proto = ctx.isSSL ? https : http;
    var remote_res;
    try {
      remote_res = await new Promise((resolve, reject) => {
        ctx.remote_req = proto.request(ctx.proxyToServerRequestOptions, resolve);
        ctx.remote_req.on('error', reject);
        ctx.requestFilters.push(new FinalRequestFilter(this, ctx));
        var tmp = req;
        ctx.requestFilters.forEach(function(filter) {
          filter.on('error', this._onError.bind(this, 'REQUEST_FILTER_ERROR', ctx));
          tmp = tmp.pipe(filter);
        }, this);
        req.resume();
      });
    } catch(err) {
      return this._onError('PROXY_TO_SERVER_REQUEST_ERROR', ctx, err);
    }

    remote_res.on('error', this._onError.bind(this, 'SERVER_TO_PROXY_RESPONSE_ERROR', ctx));
    remote_res.pause();
    ctx.remote_res = remote_res;

    try {
      await this.emit('onResponse', ctx);
      await ctx.emit('onResponse', ctx);
    } catch(err) {
      return this._onError('ON_RESPONSE_ERROR', ctx, err);
    }

    try {
      remote_res.headers['transfer-encoding'] = 'chunked';
      delete remote_res.headers['content-length'];
      remote_res.headers['connection'] = 'close';
      await this.emit('onResponseHeaders', ctx);
    } catch(err) {
      return this._onError('ON_RESPONSEHEADERS_ERROR', ctx, err);
    }

    res.writeHead(remote_res.statusCode, Proxy.filterAndCanonizeHeaders(remote_res.headers));
    ctx.responseFilters.push(new FinalResponseFilter(this, ctx));

    var tmp = remote_res;
    ctx.responseFilters.forEach(function(filter) {
      filter.on('error', this._onError.bind(this, 'RESPONSE_FILTER_ERROR', ctx));
      tmp = tmp.pipe(filter);
    }, this);

    remote_res.resume();
  }

  async _onRequestData(ctx, chunk) {
    try {
      for(var fn of this.onRequestDataHandlers.concat(ctx.onRequestDataHandlers))
        chunk = await fn(ctx, chunk);
    } catch(err) {
      return this._onError('ON_REQUEST_DATA_ERROR', ctx, err);
    }
    return chunk;
  }

  async _onResponseData(ctx, chunk) {
    try {
      for(var fn of this.onResponseDataHandlers.concat(ctx.onResponseDataHandlers))
        chunk = await fn(ctx, chunk);
    } catch(err) {
      return this._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
    }
    return chunk;
  }



  static parseHostAndPort(req, defaultPort) {
    var host = req.headers.host;
    if (!host)
      return null;

    var hostPort = Proxy.parseHost(host, defaultPort);

    // this handles paths which include the full url. This could happen if it's a proxy
    var m = req.url.match(/^http:\/\/([^\/]*)\/?(.*)$/);
    if (m) {
      var parsedUrl = url.parse(req.url);
      hostPort.host = parsedUrl.hostname;
      hostPort.port = parsedUrl.port;
      req.url = parsedUrl.path;
    }

    return hostPort;
  }

  static parseHost(hostString, defaultPort) {
    var m = hostString.match(/^http:\/\/(.*)/);
    if (m) {
      var parsedUrl = url.parse(hostString);
      return {
        host: parsedUrl.hostname,
        port: parsedUrl.port
      };
    }

    var hostPort = hostString.split(':');
    var host = hostPort[0];
    var port = hostPort.length === 2 ? +hostPort[1] : defaultPort;

    return {
      host: host,
      port: port
    };
  }

  static filterAndCanonizeHeaders(originalHeaders) {
    var headers = {};
    for (var key in originalHeaders) {
      var canonizedKey = key.trim();
      if (/^public\-key\-pins/i.test(canonizedKey)) {
        // HPKP header => filter
        continue;
      }
      headers[canonizedKey] = originalHeaders[key];
    }
    return headers;
  }
}



module.exports = Proxy;

