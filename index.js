var encodeUrl = require("encodeurl");
var escapeHtml = require("escape-html");
var parseUrl = require("parseurl");
var resolve = require("path").resolve;
var send = require("./lib/send");
var url = require("url");
var http = require("http");
var fs = require("fs");
var socketio = require("socket.io");
let appServer = null;
let io = null;
module.exports = LiveReloadExpress;
module.exports.mime = send.mime;

function LiveReloadExpress(app) {
  appServer = http.createServer(app);
  io = socketio(appServer);

  io.on("connection", socket => {
    //  console.log(socket.id);
    socket.on("targetFile", filePath => {
      //   console.log("listener", filePath);
      socket.join(filePath);
    });
  });
  return {
    static: LiveReloadExpressMiddleware,
    listen: appServer.listen.bind(appServer)
  };
}

function LiveReloadExpressMiddleware(
  root,
  options
) {
  if (!root) {
    throw new TypeError("root path required");
  }

  if (typeof root !== "string") {
    throw new TypeError(
      "root path must be a string"
    );
  }
  addWatcher(root);

  var opts = Object.create(options || null);
  var fallthrough = opts.fallthrough !== false;
  var redirect = opts.redirect !== false;
  var setHeaders = opts.setHeaders;

  if (
    setHeaders &&
    typeof setHeaders !== "function"
  ) {
    throw new TypeError(
      "option setHeaders must be function"
    );
  }

  opts.maxage = opts.maxage || opts.maxAge || 0;
  opts.root = resolve(root);

  var onDirectory = redirect
    ? createRedirectDirectoryListener()
    : createNotFoundDirectoryListener();

  return function LiveReloadExpress(
    req,
    res,
    next
  ) {
    if (
      req.method !== "GET" &&
      req.method !== "HEAD"
    ) {
      if (fallthrough) {
        return next();
      }

      res.statusCode = 405;
      res.setHeader("Allow", "GET, HEAD");
      res.setHeader("Content-Length", "0");
      res.end();
      return;
    }

    var forwardError = !fallthrough;
    var originalUrl = parseUrl.original(req);
    var path = parseUrl(req).pathname;

    if (
      path === "/" &&
      originalUrl.pathname.substr(-1) !== "/"
    ) {
      path = "";
    }

    var stream = send(req, path, opts);

    stream.on("directory", onDirectory);

    if (setHeaders) {
      stream.on("headers", setHeaders);
    }

    if (fallthrough) {
      stream.on("file", function onFile() {
        forwardError = true;
      });
    }

    stream.on("error", function error(err) {
      if (
        forwardError ||
        !(err.statusCode < 500)
      ) {
        next(err);
        return;
      }

      next();
    });

    stream.pipe(res);
  };
}

function collapseLeadingSlashes(str) {
  for (var i = 0; i < str.length; i++) {
    if (str.charCodeAt(i) !== 0x2f) {
      break;
    }
  }

  return i > 1 ? "/" + str.substr(i) : str;
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

function createNotFoundDirectoryListener() {
  return function notFound() {
    this.error(404);
  };
}

function createRedirectDirectoryListener() {
  return function redirect(res) {
    if (this.hasTrailingSlash()) {
      this.error(404);
      return;
    }

    var originalUrl = parseUrl.original(this.req);

    originalUrl.path = null;
    originalUrl.pathname = collapseLeadingSlashes(
      originalUrl.pathname + "/"
    );

    var loc = encodeUrl(url.format(originalUrl));
    var doc = createHtmlDocument(
      "Redirecting",
      'Redirecting to <a href="' +
        escapeHtml(loc) +
        '">' +
        escapeHtml(loc) +
        "</a>"
    );

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
}

function addWatcher(path) {
  let folder = resolve(path);
  //console.log(folder, "folder");
  fs.watch(folder, (event, file) => {
    let filePath = resolve(folder, file);
    if (event == "change") {
      console.log(event, filePath);
      broadcastFileChange(filePath);
    }
  });
  fs.readdir(folder, (err, files) => {
    //  console.log(files, "files");
    files.map(file => {
      let filePath = resolve(folder, file);
      let fileStat = fs.lstatSync(filePath);
      // console.log(file, filePath, "file");
      if (fileStat.isDirectory()) {
        addWatcher(filePath);
      }
    });
  });
}

function broadcastFileChange(filePath) {
  io.to(filePath.replace(/\\/g, "/")).emit(
    "fileChange",
    {}
  );
}
