var createError = require("http-errors");
var debug = require("debug")("send");
var deprecate = require("depd")("send");
var destroy = require("destroy");
var encodeUrl = require("encodeurl");
var escapeHtml = require("escape-html");
var etag = require("etag");
var fresh = require("fresh");
var fs = require("fs");
var mime = require("mime");
var ms = require("ms");
var onFinished = require("on-finished");
var parseRange = require("range-parser");
var path = require("path");
var statuses = require("statuses");
var Stream = require("stream");
var util = require("util");

var extname = path.extname;
var join = path.join;
var normalize = path.normalize;
var resolve = path.resolve;
var sep = path.sep;

var BYTES_RANGE_REGEXP = /^ *bytes=/;

var MAX_MAXAGE = 60 * 60 * 24 * 365 * 1000; // 1 year

var UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

module.exports = send;
module.exports.mime = mime;

function send(req, path, options) {
  return new SendStream(req, path, options);
}

function SendStream(req, path, options) {
  Stream.call(this);

  var opts = options || {};

  this.options = opts;
  this.path = path;
  this.req = req;

  this._acceptRanges =
    opts.acceptRanges !== undefined
      ? Boolean(opts.acceptRanges)
      : true;

  this._cacheControl =
    opts.cacheControl !== undefined
      ? Boolean(opts.cacheControl)
      : true;

  this._etag =
    opts.etag !== undefined
      ? Boolean(opts.etag)
      : true;

  this._dotfiles =
    opts.dotfiles !== undefined
      ? opts.dotfiles
      : "ignore";

  if (
    this._dotfiles !== "ignore" &&
    this._dotfiles !== "allow" &&
    this._dotfiles !== "deny"
  ) {
    throw new TypeError(
      'dotfiles option must be "allow", "deny", or "ignore"'
    );
  }

  this._hidden = Boolean(opts.hidden);

  if (opts.hidden !== undefined) {
    deprecate(
      "hidden: use dotfiles: '" +
        (this._hidden ? "allow" : "ignore") +
        "' instead"
    );
  }

  if (opts.dotfiles === undefined) {
    this._dotfiles = undefined;
  }

  this._extensions =
    opts.extensions !== undefined
      ? normalizeList(
          opts.extensions,
          "extensions option"
        )
      : [];

  this._immutable =
    opts.immutable !== undefined
      ? Boolean(opts.immutable)
      : false;

  this._index =
    opts.index !== undefined
      ? normalizeList(opts.index, "index option")
      : ["index.html"];

  this._lastModified =
    opts.lastModified !== undefined
      ? Boolean(opts.lastModified)
      : true;

  this._maxage = opts.maxAge || opts.maxage;
  this._maxage =
    typeof this._maxage === "string"
      ? ms(this._maxage)
      : Number(this._maxage);
  this._maxage = !isNaN(this._maxage)
    ? Math.min(
        Math.max(0, this._maxage),
        MAX_MAXAGE
      )
    : 0;

  this._root = opts.root
    ? resolve(opts.root)
    : null;

  if (!this._root && opts.from) {
    this.from(opts.from);
  }
}

util.inherits(SendStream, Stream);

SendStream.prototype.etag = deprecate.function(
  function etag(val) {
    this._etag = Boolean(val);
    debug("etag %s", this._etag);
    return this;
  },
  "send.etag: pass etag as option"
);

SendStream.prototype.hidden = deprecate.function(
  function hidden(val) {
    this._hidden = Boolean(val);
    this._dotfiles = undefined;
    debug("hidden %s", this._hidden);
    return this;
  },
  "send.hidden: use dotfiles option"
);

SendStream.prototype.index = deprecate.function(
  function index(paths) {
    var index = !paths
      ? []
      : normalizeList(paths, "paths argument");
    debug("index %o", paths);
    this._index = index;
    return this;
  },
  "send.index: pass index as option"
);

SendStream.prototype.root = function root(path) {
  this._root = resolve(String(path));
  debug("root %s", this._root);
  return this;
};

SendStream.prototype.from = deprecate.function(
  SendStream.prototype.root,
  "send.from: pass root as option"
);

SendStream.prototype.root = deprecate.function(
  SendStream.prototype.root,
  "send.root: pass root as option"
);

SendStream.prototype.maxage = deprecate.function(
  function maxage(maxAge) {
    this._maxage =
      typeof maxAge === "string"
        ? ms(maxAge)
        : Number(maxAge);
    this._maxage = !isNaN(this._maxage)
      ? Math.min(
          Math.max(0, this._maxage),
          MAX_MAXAGE
        )
      : 0;
    debug("max-age %d", this._maxage);
    return this;
  },
  "send.maxage: pass maxAge as option"
);

SendStream.prototype.error = function error(
  status,
  err
) {
  if (hasListeners(this, "error")) {
    return this.emit(
      "error",
      createError(status, err, {
        expose: false
      })
    );
  }

  var res = this.res;
  var msg = statuses[status] || String(status);
  var doc = createHtmlDocument(
    "Error",
    escapeHtml(msg)
  );

  clearHeaders(res);

  if (err && err.headers) {
    setHeaders(res, err.headers);
  }

  res.statusCode = status;
  res.setHeader(
    "Content-Type",
    "text/html; charset=UTF-8"
  );
  res.setHeader(
    "Content-Length",
    Buffer.byteLength(doc)
  );
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'"
  );
  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );
  res.end(doc);
};

SendStream.prototype.hasTrailingSlash = function hasTrailingSlash() {
  return this.path[this.path.length - 1] === "/";
};

SendStream.prototype.isConditionalGET = function isConditionalGET() {
  return (
    this.req.headers["if-match"] ||
    this.req.headers["if-unmodified-since"] ||
    this.req.headers["if-none-match"] ||
    this.req.headers["if-modified-since"]
  );
};

SendStream.prototype.isPreconditionFailure = function isPreconditionFailure() {
  var req = this.req;
  var res = this.res;

  var match = req.headers["if-match"];
  if (match) {
    var etag = res.getHeader("ETag");
    return (
      !etag ||
      (match !== "*" &&
        parseTokenList(match).every(function(
          match
        ) {
          return (
            match !== etag &&
            match !== "W/" + etag &&
            "W/" + match !== etag
          );
        }))
    );
  }

  var unmodifiedSince = parseHttpDate(
    req.headers["if-unmodified-since"]
  );
  if (!isNaN(unmodifiedSince)) {
    var lastModified = parseHttpDate(
      res.getHeader("Last-Modified")
    );
    return (
      isNaN(lastModified) ||
      lastModified > unmodifiedSince
    );
  }

  return false;
};

SendStream.prototype.removeContentHeaderFields = function removeContentHeaderFields() {
  var res = this.res;
  var headers = getHeaderNames(res);

  for (var i = 0; i < headers.length; i++) {
    var header = headers[i];
    if (
      header.substr(0, 8) === "content-" &&
      header !== "content-location"
    ) {
      res.removeHeader(header);
    }
  }
};

SendStream.prototype.notModified = function notModified() {
  var res = this.res;
  debug("not modified");
  this.removeContentHeaderFields();
  res.statusCode = 304;
  res.end();
};

SendStream.prototype.headersAlreadySent = function headersAlreadySent() {
  var err = new Error(
    "Can't set headers after they are sent."
  );
  debug("headers already sent");
  this.error(500, err);
};

SendStream.prototype.isCachable = function isCachable() {
  var statusCode = this.res.statusCode;
  return (
    (statusCode >= 200 && statusCode < 300) ||
    statusCode === 304
  );
};

SendStream.prototype.onStatError = function onStatError(
  error
) {
  switch (error.code) {
    case "ENAMETOOLONG":
    case "ENOENT":
    case "ENOTDIR":
      this.error(404, error);
      break;
    default:
      this.error(500, error);
      break;
  }
};

SendStream.prototype.isFresh = function isFresh() {
  return fresh(this.req.headers, {
    etag: this.res.getHeader("ETag"),
    "last-modified": this.res.getHeader(
      "Last-Modified"
    )
  });
};

SendStream.prototype.isRangeFresh = function isRangeFresh() {
  var ifRange = this.req.headers["if-range"];

  if (!ifRange) {
    return true;
  }

  if (ifRange.indexOf('"') !== -1) {
    var etag = this.res.getHeader("ETag");
    return Boolean(
      etag && ifRange.indexOf(etag) !== -1
    );
  }

  var lastModified = this.res.getHeader(
    "Last-Modified"
  );
  return (
    parseHttpDate(lastModified) <=
    parseHttpDate(ifRange)
  );
};

SendStream.prototype.redirect = function redirect(
  path
) {
  var res = this.res;

  if (hasListeners(this, "directory")) {
    this.emit("directory", res, path);
    return;
  }

  if (this.hasTrailingSlash()) {
    this.error(403);
    return;
  }

  var loc = encodeUrl(
    collapseLeadingSlashes(this.path + "/")
  );
  var doc = createHtmlDocument(
    "Redirecting",
    'Redirecting to <a href="' +
      escapeHtml(loc) +
      '">' +
      escapeHtml(loc) +
      "</a>"
  );

  // redirect
  res.statusCode = 301;
  res.setHeader(
    "Content-Type",
    "text/html; charset=UTF-8"
  );
  res.setHeader(
    "Content-Length",
    Buffer.byteLength(doc)
  );
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'"
  );
  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );
  res.setHeader("Location", loc);
  res.end(doc);
};

SendStream.prototype.pipe = function pipe(res) {
  var root = this._root;

  this.res = res;

  var path = decode(this.path);
  if (path === -1) {
    this.error(400);
    return res;
  }

  if (~path.indexOf("\0")) {
    this.error(400);
    return res;
  }

  var parts;
  if (root !== null) {
    if (path) {
      path = normalize("." + sep + path);
    }

    if (UP_PATH_REGEXP.test(path)) {
      debug('malicious path "%s"', path);
      this.error(403);
      return res;
    }

    parts = path.split(sep);

    path = normalize(join(root, path));
  } else {
    if (UP_PATH_REGEXP.test(path)) {
      debug('malicious path "%s"', path);
      this.error(403);
      return res;
    }

    parts = normalize(path).split(sep);

    path = resolve(path);
  }

  if (containsDotFile(parts)) {
    var access = this._dotfiles;

    if (access === undefined) {
      access =
        parts[parts.length - 1][0] === "."
          ? this._hidden
            ? "allow"
            : "ignore"
          : "allow";
    }

    debug('%s dotfile "%s"', access, path);
    switch (access) {
      case "allow":
        break;
      case "deny":
        this.error(403);
        return res;
      case "ignore":
      default:
        this.error(404);
        return res;
    }
  }

  if (
    this._index.length &&
    this.hasTrailingSlash()
  ) {
    this.sendIndex(path);
    return res;
  }

  this.sendFile(path);
  return res;
};

SendStream.prototype.send = function send(
  path,
  stat
) {
  var len = stat.size;
  var options = this.options;
  var opts = {};
  var res = this.res;
  var req = this.req;
  var ranges = req.headers.range;
  var offset = options.start || 0;

  if (headersSent(res)) {
    this.headersAlreadySent();
    return;
  }

  debug('pipe "%s"', path);

  this.setHeader(path, stat);

  this.type(path);

  if (this.isConditionalGET()) {
    if (this.isPreconditionFailure()) {
      this.error(412);
      return;
    }

    if (this.isCachable() && this.isFresh()) {
      this.notModified();
      return;
    }
  }

  len = Math.max(0, len - offset);
  if (options.end !== undefined) {
    var bytes = options.end - offset + 1;
    if (len > bytes) len = bytes;
  }

  if (
    this._acceptRanges &&
    BYTES_RANGE_REGEXP.test(ranges)
  ) {
    ranges = parseRange(len, ranges, {
      combine: true
    });

    if (!this.isRangeFresh()) {
      debug("range stale");
      ranges = -2;
    }

    if (ranges === -1) {
      debug("range unsatisfiable");

      res.setHeader(
        "Content-Range",
        contentRange("bytes", len)
      );

      return this.error(416, {
        headers: {
          "Content-Range": res.getHeader(
            "Content-Range"
          )
        }
      });
    }

    if (ranges !== -2 && ranges.length === 1) {
      debug("range %j", ranges);

      res.statusCode = 206;
      res.setHeader(
        "Content-Range",
        contentRange("bytes", len, ranges[0])
      );

      offset += ranges[0].start;
      len = ranges[0].end - ranges[0].start + 1;
    }
  }

  for (var prop in options) {
    opts[prop] = options[prop];
  }

  opts.start = offset;
  opts.end = Math.max(offset, offset + len - 1);
  let ScriptTag = "";
  console.log(
    path,
    isHTMLFile(path),
    "checking html"
  );
  if (isHTMLFile(path)) {
    ScriptTag = makeCallbackScript(path);
  } else {
    console.log(path, "is not html");
  }
  res.setHeader(
    "Content-Length",
    len + ScriptTag.length
  );

  if (req.method === "HEAD") {
    res.end();
    return;
  }

  this.stream(path, opts, ScriptTag);
};

SendStream.prototype.sendFile = function sendFile(
  path
) {
  var i = 0;
  var self = this;

  debug('stat "%s"', path);
  fs.stat(path, function onstat(err, stat) {
    if (
      err &&
      err.code === "ENOENT" &&
      !extname(path) &&
      path[path.length - 1] !== sep
    ) {
      return next(err);
    }
    if (err) return self.onStatError(err);
    if (stat.isDirectory())
      return self.redirect(path);
    self.emit("file", path, stat);
    self.send(path, stat);
  });

  function next(err) {
    if (self._extensions.length <= i) {
      return err
        ? self.onStatError(err)
        : self.error(404);
    }

    var p = path + "." + self._extensions[i++];

    debug('stat "%s"', p);
    fs.stat(p, function(err, stat) {
      if (err) return next(err);
      if (stat.isDirectory()) return next();
      self.emit("file", p, stat);
      self.send(p, stat);
    });
  }
};

SendStream.prototype.sendIndex = function sendIndex(
  path
) {
  var i = -1;
  var self = this;

  function next(err) {
    if (++i >= self._index.length) {
      if (err) return self.onStatError(err);
      return self.error(404);
    }

    var p = join(path, self._index[i]);

    debug('stat "%s"', p);
    fs.stat(p, function(err, stat) {
      if (err) return next(err);
      if (stat.isDirectory()) return next();
      self.emit("file", p, stat);
      self.send(p, stat);
    });
  }

  next();
};

SendStream.prototype.stream = function stream(
  path,
  options,
  scriptTag
) {
  var finished = false;
  var self = this;
  var res = this.res;
  //console.log(res, path, options);
  var stream = fs.createReadStream(path, options);
  this.emit("stream", stream);
  //res.write("hello");
  if (scriptTag.length == 0) stream.pipe(res);

  onFinished(res, function onfinished() {
    finished = true;
    destroy(stream);
  });

  if (scriptTag.length) {
    stream.on("data", data => {
      let str = data.toString();
      str += scriptTag;
      res.write(str);
      res.end();
    });
  }

  stream.on("error", function onerror(err) {
    if (finished) return;
    finished = true;
    destroy(stream);
    self.onStatError(err);
  });

  stream.on("end", function onend() {
    self.emit("end");
  });
};

SendStream.prototype.type = function type(path) {
  var res = this.res;

  if (res.getHeader("Content-Type")) return;

  var type = mime.lookup(path);

  if (!type) {
    debug("no content-type");
    return;
  }

  var charset = mime.charsets.lookup(type);

  debug("content-type %s", type);
  res.setHeader(
    "Content-Type",
    type + (charset ? "; charset=" + charset : "")
  );
};

SendStream.prototype.setHeader = function setHeader(
  path,
  stat
) {
  var res = this.res;

  this.emit("headers", res, path, stat);

  if (
    this._acceptRanges &&
    !res.getHeader("Accept-Ranges")
  ) {
    debug("accept ranges");
    res.setHeader("Accept-Ranges", "bytes");
  }

  if (
    this._cacheControl &&
    !res.getHeader("Cache-Control")
  ) {
    var cacheControl =
      "public, max-age=" +
      Math.floor(this._maxage / 1000);

    if (this._immutable) {
      cacheControl += ", immutable";
    }

    debug("cache-control %s", cacheControl);
    res.setHeader("Cache-Control", cacheControl);
  }

  if (
    this._lastModified &&
    !res.getHeader("Last-Modified")
  ) {
    var modified = stat.mtime.toUTCString();
    debug("modified %s", modified);
    res.setHeader("Last-Modified", modified);
  }

  if (this._etag && !res.getHeader("ETag")) {
    var val = etag(stat);
    debug("etag %s", val);
    res.setHeader("ETag", val);
  }
};

function clearHeaders(res) {
  var headers = getHeaderNames(res);

  for (var i = 0; i < headers.length; i++) {
    res.removeHeader(headers[i]);
  }
}

function collapseLeadingSlashes(str) {
  for (var i = 0; i < str.length; i++) {
    if (str[i] !== "/") {
      break;
    }
  }

  return i > 1 ? "/" + str.substr(i) : str;
}

function containsDotFile(parts) {
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (part.length > 1 && part[0] === ".") {
      return true;
    }
  }

  return false;
}

function contentRange(type, size, range) {
  return (
    type +
    " " +
    (range
      ? range.start + "-" + range.end
      : "*") +
    "/" +
    size
  );
}

function createHtmlDocument(title, body) {
  return (
    "<!DOCTYPE html>\n" +
    '<html lang="en">\n' +
    "<head>\n" +
    '<meta charset="utf-8">\n' +
    "<title>" +
    title +
    "</title>\n" +
    "</head>\n" +
    "<body>\n" +
    "<pre>" +
    body +
    "</pre>\n" +
    "</body>\n" +
    "</html>\n"
  );
}

function decode(path) {
  try {
    return decodeURIComponent(path);
  } catch (err) {
    return -1;
  }
}

function getHeaderNames(res) {
  return typeof res.getHeaderNames !== "function"
    ? Object.keys(res._headers || {})
    : res.getHeaderNames();
}

function hasListeners(emitter, type) {
  var count =
    typeof emitter.listenerCount !== "function"
      ? emitter.listeners(type).length
      : emitter.listenerCount(type);

  return count > 0;
}

function headersSent(res) {
  return typeof res.headersSent !== "boolean"
    ? Boolean(res._header)
    : res.headersSent;
}

function normalizeList(val, name) {
  var list = [].concat(val || []);

  for (var i = 0; i < list.length; i++) {
    if (typeof list[i] !== "string") {
      throw new TypeError(
        name +
          " must be array of strings or false"
      );
    }
  }

  return list;
}

function parseHttpDate(date) {
  var timestamp = date && Date.parse(date);

  return typeof timestamp === "number"
    ? timestamp
    : NaN;
}

function parseTokenList(str) {
  var end = 0;
  var list = [];
  var start = 0;
  for (
    var i = 0, len = str.length;
    i < len;
    i++
  ) {
    switch (str.charCodeAt(i)) {
      case 0x20:
        if (start === end) {
          start = end = i + 1;
        }
        break;
      case 0x2c:
        list.push(str.substring(start, end));
        start = end = i + 1;
        break;
      default:
        end = i + 1;
        break;
    }
  }

  list.push(str.substring(start, end));

  return list;
}

function setHeaders(res, headers) {
  var keys = Object.keys(headers);

  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    res.setHeader(key, headers[key]);
  }
}

function makeCallbackScript(path) {
  let scriptTag = `<script src="/socket.io/socket.io.js"></script><script>
      let socket = io();
      let filePath = "${path.replace(
        /\\/g,
        "/"
      )}";
      console.log("LIVE RELOAD EXPRESS","filePath =>",filePath);
      socket.on("connect",()=>{
        console.log("LIVE RELOAD EXPRESS","SOCKET CONNECTED",socket.id);
        socket.emit("targetFile",filePath);
      })
      socket.on("fileChange",()=>{
        location.reload();
      })
    </script>`;
  // console.log(scriptTag.length);
  return scriptTag;
}

function isHTMLFile(path) {
  return path.split(".").pop() == "html";
}
