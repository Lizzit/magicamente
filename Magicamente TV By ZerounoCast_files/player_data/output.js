(() => {
  let __async = (__this, __arguments, generator) => new Promise((resolve, reject) => {
    let fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    }, rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    }, step = (result) => result.done ? resolve(result.value) : Promise.resolve(result.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });

  // templates/jssdk/aws-sdk-2.706.0.min.js
  _xamzrequire = function() {
    function e(t, r, n) {
      function i(s2, a) {
        if (!r[s2]) {
          if (!t[s2]) {
            var u = false;
            if (!a && u)
              return u(s2, true);
            if (o)
              return o(s2, true);
            var c = new Error("Cannot find module '" + s2 + "'");
            throw c.code = "MODULE_NOT_FOUND", c;
          }
          var l = r[s2] = {exports: {}};
          t[s2][0].call(l.exports, function(e2) {
            return i(t[s2][1][e2] || e2);
          }, l, l.exports, e, t, r, n);
        }
        return r[s2].exports;
      }
      for (var o = false, s = 0; s < n.length; s++)
        i(n[s]);
      return i;
    }
    return e;
  }()({38: [function(e, t, r) {
    (function(r2) {
      function n(e2, t2) {
        if ("string" == typeof e2) {
          if (["legacy", "regional"].indexOf(e2.toLowerCase()) >= 0)
            return e2.toLowerCase();
          throw o.util.error(new Error(), t2);
        }
      }
      function i(e2, t2) {
        e2 = e2 || {};
        var i2;
        if (e2[t2.clientConfig] && (i2 = n(e2[t2.clientConfig], {code: "InvalidConfiguration", message: 'invalid "' + t2.clientConfig + '" configuration. Expect "legacy"  or "regional". Got "' + e2[t2.clientConfig] + '".'})))
          return i2;
        if (!o.util.isNode())
          return i2;
        if (Object.prototype.hasOwnProperty.call(r2.env, t2.env)) {
          if (i2 = n(r2.env[t2.env], {code: "InvalidEnvironmentalVariable", message: "invalid " + t2.env + ' environmental variable. Expect "legacy"  or "regional". Got "' + r2.env[t2.env] + '".'}))
            return i2;
        }
        var s = {};
        try {
          s = o.util.getProfilesFromSharedConfig(o.util.iniLoader)[r2.env.AWS_PROFILE || o.util.defaultProfile];
        } catch (e3) {
        }
        if (s && Object.prototype.hasOwnProperty.call(s, t2.sharedConfig)) {
          if (i2 = n(s[t2.sharedConfig], {code: "InvalidConfiguration", message: "invalid " + t2.sharedConfig + ' profile config. Expect "legacy"  or "regional". Got "' + s[t2.sharedConfig] + '".'}))
            return i2;
        }
        return i2;
      }
      var o = e("./core");
      t.exports = i;
    }).call(this, e("_process"));
  }, {"./core": 39, _process: 8}], 39: [function(e, t, r) {
    var n = {util: e("./util")};
    ({}).toString(), t.exports = n, n.util.update(n, {VERSION: "2.706.0", Signers: {}, Protocol: {Json: e("./protocol/json"), Query: e("./protocol/query"), Rest: e("./protocol/rest"), RestJson: e("./protocol/rest_json"), RestXml: e("./protocol/rest_xml")}, XML: {Builder: e("./xml/builder"), Parser: null}, JSON: {Builder: e("./json/builder"), Parser: e("./json/parser")}, Model: {Api: e("./model/api"), Operation: e("./model/operation"), Shape: e("./model/shape"), Paginator: e("./model/paginator"), ResourceWaiter: e("./model/resource_waiter")}, apiLoader: e("./api_loader"), EndpointCache: e("../vendor/endpoint-cache").EndpointCache}), e("./sequential_executor"), e("./service"), e("./config"), e("./http"), e("./event_listeners"), e("./request"), e("./response"), e("./resource_waiter"), e("./signers/request_signer"), e("./param_validator"), n.events = new n.SequentialExecutor(), n.util.memoizedProperty(n, "endpointCache", function() {
      return new n.EndpointCache(n.config.endpointCacheSize);
    }, true);
  }, {"../vendor/endpoint-cache": 125, "./api_loader": 27, "./config": 37, "./event_listeners": 60, "./http": 61, "./json/builder": 63, "./json/parser": 64, "./model/api": 65, "./model/operation": 67, "./model/paginator": 68, "./model/resource_waiter": 69, "./model/shape": 70, "./param_validator": 71, "./protocol/json": 74, "./protocol/query": 75, "./protocol/rest": 76, "./protocol/rest_json": 77, "./protocol/rest_xml": 78, "./request": 84, "./resource_waiter": 85, "./response": 86, "./sequential_executor": 88, "./service": 89, "./signers/request_signer": 110, "./util": 118, "./xml/builder": 120}], 125: [function(e, t, r) {
    "use strict";
    Object.defineProperty(r, "__esModule", {value: true});
    var n = e("./utils/LRU"), i = 1e3, o = function() {
      function e2(e3) {
        void 0 === e3 && (e3 = i), this.maxSize = e3, this.cache = new n.LRUCache(e3);
      }
      return Object.defineProperty(e2.prototype, "size", {get: function() {
        return this.cache.length;
      }, enumerable: true, configurable: true}), e2.prototype.put = function(t2, r2) {
        var n2 = "string" != typeof t2 ? e2.getKeyString(t2) : t2, i2 = this.populateValue(r2);
        this.cache.put(n2, i2);
      }, e2.prototype.get = function(t2) {
        var r2 = "string" != typeof t2 ? e2.getKeyString(t2) : t2, n2 = Date.now(), i2 = this.cache.get(r2);
        if (i2)
          for (var o2 = 0; o2 < i2.length; o2++) {
            var s = i2[o2];
            if (s.Expire < n2)
              return void this.cache.remove(r2);
          }
        return i2;
      }, e2.getKeyString = function(e3) {
        for (var t2 = [], r2 = Object.keys(e3).sort(), n2 = 0; n2 < r2.length; n2++) {
          var i2 = r2[n2];
          void 0 !== e3[i2] && t2.push(e3[i2]);
        }
        return t2.join(" ");
      }, e2.prototype.populateValue = function(e3) {
        var t2 = Date.now();
        return e3.map(function(e4) {
          return {Address: e4.Address || "", Expire: t2 + 60 * (e4.CachePeriodInMinutes || 1) * 1e3};
        });
      }, e2.prototype.empty = function() {
        this.cache.empty();
      }, e2.prototype.remove = function(t2) {
        var r2 = "string" != typeof t2 ? e2.getKeyString(t2) : t2;
        this.cache.remove(r2);
      }, e2;
    }();
    r.EndpointCache = o;
  }, {"./utils/LRU": 126}], 126: [function(e, t, r) {
    "use strict";
    Object.defineProperty(r, "__esModule", {value: true});
    var n = function() {
      function e2(e3, t2) {
        this.key = e3, this.value = t2;
      }
      return e2;
    }(), i = function() {
      function e2(e3) {
        if (this.nodeMap = {}, this.size = 0, "number" != typeof e3 || e3 < 1)
          throw new Error("Cache size can only be positive number");
        this.sizeLimit = e3;
      }
      return Object.defineProperty(e2.prototype, "length", {get: function() {
        return this.size;
      }, enumerable: true, configurable: true}), e2.prototype.prependToList = function(e3) {
        this.headerNode ? (this.headerNode.prev = e3, e3.next = this.headerNode) : this.tailNode = e3, this.headerNode = e3, this.size++;
      }, e2.prototype.removeFromTail = function() {
        if (this.tailNode) {
          var e3 = this.tailNode, t2 = e3.prev;
          return t2 && (t2.next = void 0), e3.prev = void 0, this.tailNode = t2, this.size--, e3;
        }
      }, e2.prototype.detachFromList = function(e3) {
        this.headerNode === e3 && (this.headerNode = e3.next), this.tailNode === e3 && (this.tailNode = e3.prev), e3.prev && (e3.prev.next = e3.next), e3.next && (e3.next.prev = e3.prev), e3.next = void 0, e3.prev = void 0, this.size--;
      }, e2.prototype.get = function(e3) {
        if (this.nodeMap[e3]) {
          var t2 = this.nodeMap[e3];
          return this.detachFromList(t2), this.prependToList(t2), t2.value;
        }
      }, e2.prototype.remove = function(e3) {
        if (this.nodeMap[e3]) {
          var t2 = this.nodeMap[e3];
          this.detachFromList(t2), delete this.nodeMap[e3];
        }
      }, e2.prototype.put = function(e3, t2) {
        if (this.nodeMap[e3])
          this.remove(e3);
        else if (this.size === this.sizeLimit) {
          var r2 = this.removeFromTail(), i2 = r2.key;
          delete this.nodeMap[i2];
        }
        var o = new n(e3, t2);
        this.nodeMap[e3] = o, this.prependToList(o);
      }, e2.prototype.empty = function() {
        for (var e3 = Object.keys(this.nodeMap), t2 = 0; t2 < e3.length; t2++) {
          var r2 = e3[t2], n2 = this.nodeMap[r2];
          this.detachFromList(n2), delete this.nodeMap[r2];
        }
      }, e2;
    }();
    r.LRUCache = i;
  }, {}], 120: [function(e, t, r) {
    function n() {
    }
    function i(e2, t2, r2) {
      switch (r2.type) {
        case "structure":
          return o(e2, t2, r2);
        case "map":
          return s(e2, t2, r2);
        case "list":
          return a(e2, t2, r2);
        default:
          return u(e2, t2, r2);
      }
    }
    function o(e2, t2, r2) {
      l.arrayEach(r2.memberNames, function(n2) {
        var o2 = r2.members[n2];
        if ("body" === o2.location) {
          var s2 = t2[n2], a2 = o2.name;
          if (void 0 !== s2 && null !== s2)
            if (o2.isXmlAttribute)
              e2.addAttribute(a2, s2);
            else if (o2.flattened)
              i(e2, s2, o2);
            else {
              var u2 = new h(a2);
              e2.addChildNode(u2), c(u2, o2), i(u2, s2, o2);
            }
        }
      });
    }
    function s(e2, t2, r2) {
      var n2 = r2.key.name || "key", o2 = r2.value.name || "value";
      l.each(t2, function(t3, s2) {
        var a2 = new h(r2.flattened ? r2.name : "entry");
        e2.addChildNode(a2);
        var u2 = new h(n2), c2 = new h(o2);
        a2.addChildNode(u2), a2.addChildNode(c2), i(u2, t3, r2.key), i(c2, s2, r2.value);
      });
    }
    function a(e2, t2, r2) {
      r2.flattened ? l.arrayEach(t2, function(t3) {
        var n2 = r2.member.name || r2.name, o2 = new h(n2);
        e2.addChildNode(o2), i(o2, t3, r2.member);
      }) : l.arrayEach(t2, function(t3) {
        var n2 = r2.member.name || "member", o2 = new h(n2);
        e2.addChildNode(o2), i(o2, t3, r2.member);
      });
    }
    function u(e2, t2, r2) {
      e2.addChildNode(new p(r2.toWireFormat(t2)));
    }
    function c(e2, t2, r2) {
      var n2, i2 = "xmlns";
      t2.xmlNamespaceUri ? (n2 = t2.xmlNamespaceUri, t2.xmlNamespacePrefix && (i2 += ":" + t2.xmlNamespacePrefix)) : r2 && t2.api.xmlNamespaceUri && (n2 = t2.api.xmlNamespaceUri), n2 && e2.addAttribute(i2, n2);
    }
    var l = e("../util"), h = e("./xml-node").XmlNode, p = e("./xml-text").XmlText;
    n.prototype.toXML = function(e2, t2, r2, n2) {
      var o2 = new h(r2);
      return c(o2, t2, true), i(o2, e2, t2), o2.children.length > 0 || n2 ? o2.toString() : "";
    }, t.exports = n;
  }, {"../util": 118, "./xml-node": 123, "./xml-text": 124}], 124: [function(e, t, r) {
    function n(e2) {
      this.value = e2;
    }
    var i = e("./escape-element").escapeElement;
    n.prototype.toString = function() {
      return i("" + this.value);
    }, t.exports = {XmlText: n};
  }, {"./escape-element": 122}], 122: [function(e, t, r) {
    function n(e2) {
      return e2.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
    t.exports = {escapeElement: n};
  }, {}], 123: [function(e, t, r) {
    function n(e2, t2) {
      void 0 === t2 && (t2 = []), this.name = e2, this.children = t2, this.attributes = {};
    }
    var i = e("./escape-attribute").escapeAttribute;
    n.prototype.addAttribute = function(e2, t2) {
      return this.attributes[e2] = t2, this;
    }, n.prototype.addChildNode = function(e2) {
      return this.children.push(e2), this;
    }, n.prototype.removeAttribute = function(e2) {
      return delete this.attributes[e2], this;
    }, n.prototype.toString = function() {
      for (var e2 = Boolean(this.children.length), t2 = "<" + this.name, r2 = this.attributes, n2 = 0, o = Object.keys(r2); n2 < o.length; n2++) {
        var s = o[n2], a = r2[s];
        void 0 !== a && null !== a && (t2 += " " + s + '="' + i("" + a) + '"');
      }
      return t2 += e2 ? ">" + this.children.map(function(e3) {
        return e3.toString();
      }).join("") + "</" + this.name + ">" : "/>";
    }, t.exports = {XmlNode: n};
  }, {"./escape-attribute": 121}], 121: [function(e, t, r) {
    function n(e2) {
      return e2.replace(/&/g, "&amp;").replace(/'/g, "&apos;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
    t.exports = {escapeAttribute: n};
  }, {}], 110: [function(e, t, r) {
    var n = e("../core"), i = n.util.inherit;
    n.Signers.RequestSigner = i({constructor: function(e2) {
      this.request = e2;
    }, setServiceClientId: function(e2) {
      this.serviceClientId = e2;
    }, getServiceClientId: function() {
      return this.serviceClientId;
    }}), n.Signers.RequestSigner.getVersion = function(e2) {
      switch (e2) {
        case "v2":
          return n.Signers.V2;
        case "v3":
          return n.Signers.V3;
        case "s3v4":
        case "v4":
          return n.Signers.V4;
        case "s3":
          return n.Signers.S3;
        case "v3https":
          return n.Signers.V3Https;
      }
      throw new Error("Unknown signing version " + e2);
    }, e("./v2"), e("./v3"), e("./v3https"), e("./v4"), e("./s3"), e("./presign");
  }, {"../core": 39, "./presign": 109, "./s3": 111, "./v2": 112, "./v3": 113, "./v3https": 114, "./v4": 115}], 115: [function(e, t, r) {
    var n = e("../core"), i = e("./v4_credentials"), o = n.util.inherit;
    n.Signers.V4 = o(n.Signers.RequestSigner, {constructor: function(e2, t2, r2) {
      n.Signers.RequestSigner.call(this, e2), this.serviceName = t2, r2 = r2 || {}, this.signatureCache = "boolean" != typeof r2.signatureCache || r2.signatureCache, this.operation = r2.operation, this.signatureVersion = r2.signatureVersion;
    }, algorithm: "AWS4-HMAC-SHA256", addAuthorization: function(e2, t2) {
      var r2 = n.util.date.iso8601(t2).replace(/[:\-]|\.\d{3}/g, "");
      this.isPresigned() ? this.updateForPresigned(e2, r2) : this.addHeaders(e2, r2), this.request.headers.Authorization = this.authorization(e2, r2);
    }, addHeaders: function(e2, t2) {
      this.request.headers["X-Amz-Date"] = t2, e2.sessionToken && (this.request.headers["x-amz-security-token"] = e2.sessionToken);
    }, updateForPresigned: function(e2, t2) {
      var r2 = this.credentialString(t2), i2 = {"X-Amz-Date": t2, "X-Amz-Algorithm": this.algorithm, "X-Amz-Credential": e2.accessKeyId + "/" + r2, "X-Amz-Expires": this.request.headers["presigned-expires"], "X-Amz-SignedHeaders": this.signedHeaders()};
      e2.sessionToken && (i2["X-Amz-Security-Token"] = e2.sessionToken), this.request.headers["Content-Type"] && (i2["Content-Type"] = this.request.headers["Content-Type"]), this.request.headers["Content-MD5"] && (i2["Content-MD5"] = this.request.headers["Content-MD5"]), this.request.headers["Cache-Control"] && (i2["Cache-Control"] = this.request.headers["Cache-Control"]), n.util.each.call(this, this.request.headers, function(e3, t3) {
        if ("presigned-expires" !== e3 && this.isSignableHeader(e3)) {
          var r3 = e3.toLowerCase();
          0 === r3.indexOf("x-amz-meta-") ? i2[r3] = t3 : 0 === r3.indexOf("x-amz-") && (i2[e3] = t3);
        }
      });
      var o2 = this.request.path.indexOf("?") >= 0 ? "&" : "?";
      this.request.path += o2 + n.util.queryParamsToString(i2);
    }, authorization: function(e2, t2) {
      var r2 = [], n2 = this.credentialString(t2);
      return r2.push(this.algorithm + " Credential=" + e2.accessKeyId + "/" + n2), r2.push("SignedHeaders=" + this.signedHeaders()), r2.push("Signature=" + this.signature(e2, t2)), r2.join(", ");
    }, signature: function(e2, t2) {
      var r2 = i.getSigningKey(e2, t2.substr(0, 8), this.request.region, this.serviceName, this.signatureCache);
      return n.util.crypto.hmac(r2, this.stringToSign(t2), "hex");
    }, stringToSign: function(e2) {
      var t2 = [];
      return t2.push("AWS4-HMAC-SHA256"), t2.push(e2), t2.push(this.credentialString(e2)), t2.push(this.hexEncodedHash(this.canonicalString())), t2.join("\n");
    }, canonicalString: function() {
      var e2 = [], t2 = this.request.pathname();
      return "s3" !== this.serviceName && "s3v4" !== this.signatureVersion && (t2 = n.util.uriEscapePath(t2)), e2.push(this.request.method), e2.push(t2), e2.push(this.request.search()), e2.push(this.canonicalHeaders() + "\n"), e2.push(this.signedHeaders()), e2.push(this.hexEncodedBodyHash()), e2.join("\n");
    }, canonicalHeaders: function() {
      var e2 = [];
      n.util.each.call(this, this.request.headers, function(t3, r2) {
        e2.push([t3, r2]);
      }), e2.sort(function(e3, t3) {
        return e3[0].toLowerCase() < t3[0].toLowerCase() ? -1 : 1;
      });
      var t2 = [];
      return n.util.arrayEach.call(this, e2, function(e3) {
        var r2 = e3[0].toLowerCase();
        if (this.isSignableHeader(r2)) {
          var i2 = e3[1];
          if (void 0 === i2 || null === i2 || "function" != typeof i2.toString)
            throw n.util.error(new Error("Header " + r2 + " contains invalid value"), {code: "InvalidHeader"});
          t2.push(r2 + ":" + this.canonicalHeaderValues(i2.toString()));
        }
      }), t2.join("\n");
    }, canonicalHeaderValues: function(e2) {
      return e2.replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
    }, signedHeaders: function() {
      var e2 = [];
      return n.util.each.call(this, this.request.headers, function(t2) {
        t2 = t2.toLowerCase(), this.isSignableHeader(t2) && e2.push(t2);
      }), e2.sort().join(";");
    }, credentialString: function(e2) {
      return i.createScope(e2.substr(0, 8), this.request.region, this.serviceName);
    }, hexEncodedHash: function(e2) {
      return n.util.crypto.sha256(e2, "hex");
    }, hexEncodedBodyHash: function() {
      var e2 = this.request;
      return this.isPresigned() && "s3" === this.serviceName && !e2.body ? "UNSIGNED-PAYLOAD" : e2.headers["X-Amz-Content-Sha256"] ? e2.headers["X-Amz-Content-Sha256"] : this.hexEncodedHash(this.request.body || "");
    }, unsignableHeaders: ["authorization", "content-type", "content-length", "user-agent", "presigned-expires", "expect", "x-amzn-trace-id"], isSignableHeader: function(e2) {
      return 0 === e2.toLowerCase().indexOf("x-amz-") || this.unsignableHeaders.indexOf(e2) < 0;
    }, isPresigned: function() {
      return !!this.request.headers["presigned-expires"];
    }}), t.exports = n.Signers.V4;
  }, {"../core": 39, "./v4_credentials": 116}], 116: [function(e, t, r) {
    var n = e("../core"), i = {}, o = [];
    t.exports = {createScope: function(e2, t2, r2) {
      return [e2.substr(0, 8), t2, r2, "aws4_request"].join("/");
    }, getSigningKey: function(e2, t2, r2, s, a) {
      var u = n.util.crypto.hmac(e2.secretAccessKey, e2.accessKeyId, "base64"), c = [u, t2, r2, s].join("_");
      if ((a = false !== a) && c in i)
        return i[c];
      var l = n.util.crypto.hmac("AWS4" + e2.secretAccessKey, t2, "buffer"), h = n.util.crypto.hmac(l, r2, "buffer"), p = n.util.crypto.hmac(h, s, "buffer"), f = n.util.crypto.hmac(p, "aws4_request", "buffer");
      return a && (i[c] = f, o.push(c), o.length > 50 && delete i[o.shift()]), f;
    }, emptyCache: function() {
      i = {}, o = [];
    }};
  }, {"../core": 39}], 114: [function(e, t, r) {
    var n = e("../core"), i = n.util.inherit;
    e("./v3"), n.Signers.V3Https = i(n.Signers.V3, {authorization: function(e2) {
      return "AWS3-HTTPS AWSAccessKeyId=" + e2.accessKeyId + ",Algorithm=HmacSHA256,Signature=" + this.signature(e2);
    }, stringToSign: function() {
      return this.request.headers["X-Amz-Date"];
    }}), t.exports = n.Signers.V3Https;
  }, {"../core": 39, "./v3": 113}], 113: [function(e, t, r) {
    var n = e("../core"), i = n.util.inherit;
    n.Signers.V3 = i(n.Signers.RequestSigner, {addAuthorization: function(e2, t2) {
      var r2 = n.util.date.rfc822(t2);
      this.request.headers["X-Amz-Date"] = r2, e2.sessionToken && (this.request.headers["x-amz-security-token"] = e2.sessionToken), this.request.headers["X-Amzn-Authorization"] = this.authorization(e2, r2);
    }, authorization: function(e2) {
      return "AWS3 AWSAccessKeyId=" + e2.accessKeyId + ",Algorithm=HmacSHA256,SignedHeaders=" + this.signedHeaders() + ",Signature=" + this.signature(e2);
    }, signedHeaders: function() {
      var e2 = [];
      return n.util.arrayEach(this.headersToSign(), function(t2) {
        e2.push(t2.toLowerCase());
      }), e2.sort().join(";");
    }, canonicalHeaders: function() {
      var e2 = this.request.headers, t2 = [];
      return n.util.arrayEach(this.headersToSign(), function(r2) {
        t2.push(r2.toLowerCase().trim() + ":" + String(e2[r2]).trim());
      }), t2.sort().join("\n") + "\n";
    }, headersToSign: function() {
      var e2 = [];
      return n.util.each(this.request.headers, function(t2) {
        ("Host" === t2 || "Content-Encoding" === t2 || t2.match(/^X-Amz/i)) && e2.push(t2);
      }), e2;
    }, signature: function(e2) {
      return n.util.crypto.hmac(e2.secretAccessKey, this.stringToSign(), "base64");
    }, stringToSign: function() {
      var e2 = [];
      return e2.push(this.request.method), e2.push("/"), e2.push(""), e2.push(this.canonicalHeaders()), e2.push(this.request.body), n.util.crypto.sha256(e2.join("\n"));
    }}), t.exports = n.Signers.V3;
  }, {"../core": 39}], 112: [function(e, t, r) {
    var n = e("../core"), i = n.util.inherit;
    n.Signers.V2 = i(n.Signers.RequestSigner, {addAuthorization: function(e2, t2) {
      t2 || (t2 = n.util.date.getDate());
      var r2 = this.request;
      r2.params.Timestamp = n.util.date.iso8601(t2), r2.params.SignatureVersion = "2", r2.params.SignatureMethod = "HmacSHA256", r2.params.AWSAccessKeyId = e2.accessKeyId, e2.sessionToken && (r2.params.SecurityToken = e2.sessionToken), delete r2.params.Signature, r2.params.Signature = this.signature(e2), r2.body = n.util.queryParamsToString(r2.params), r2.headers["Content-Length"] = r2.body.length;
    }, signature: function(e2) {
      return n.util.crypto.hmac(e2.secretAccessKey, this.stringToSign(), "base64");
    }, stringToSign: function() {
      var e2 = [];
      return e2.push(this.request.method), e2.push(this.request.endpoint.host.toLowerCase()), e2.push(this.request.pathname()), e2.push(n.util.queryParamsToString(this.request.params)), e2.join("\n");
    }}), t.exports = n.Signers.V2;
  }, {"../core": 39}], 111: [function(e, t, r) {
    var n = e("../core"), i = n.util.inherit;
    n.Signers.S3 = i(n.Signers.RequestSigner, {subResources: {acl: 1, accelerate: 1, analytics: 1, cors: 1, lifecycle: 1, delete: 1, inventory: 1, location: 1, logging: 1, metrics: 1, notification: 1, partNumber: 1, policy: 1, requestPayment: 1, replication: 1, restore: 1, tagging: 1, torrent: 1, uploadId: 1, uploads: 1, versionId: 1, versioning: 1, versions: 1, website: 1}, responseHeaders: {"response-content-type": 1, "response-content-language": 1, "response-expires": 1, "response-cache-control": 1, "response-content-disposition": 1, "response-content-encoding": 1}, addAuthorization: function(e2, t2) {
      this.request.headers["presigned-expires"] || (this.request.headers["X-Amz-Date"] = n.util.date.rfc822(t2)), e2.sessionToken && (this.request.headers["x-amz-security-token"] = e2.sessionToken);
      var r2 = this.sign(e2.secretAccessKey, this.stringToSign()), i2 = "AWS " + e2.accessKeyId + ":" + r2;
      this.request.headers.Authorization = i2;
    }, stringToSign: function() {
      var e2 = this.request, t2 = [];
      t2.push(e2.method), t2.push(e2.headers["Content-MD5"] || ""), t2.push(e2.headers["Content-Type"] || ""), t2.push(e2.headers["presigned-expires"] || "");
      var r2 = this.canonicalizedAmzHeaders();
      return r2 && t2.push(r2), t2.push(this.canonicalizedResource()), t2.join("\n");
    }, canonicalizedAmzHeaders: function() {
      var e2 = [];
      n.util.each(this.request.headers, function(t3) {
        t3.match(/^x-amz-/i) && e2.push(t3);
      }), e2.sort(function(e3, t3) {
        return e3.toLowerCase() < t3.toLowerCase() ? -1 : 1;
      });
      var t2 = [];
      return n.util.arrayEach.call(this, e2, function(e3) {
        t2.push(e3.toLowerCase() + ":" + String(this.request.headers[e3]));
      }), t2.join("\n");
    }, canonicalizedResource: function() {
      var e2 = this.request, t2 = e2.path.split("?"), r2 = t2[0], i2 = t2[1], o = "";
      if (e2.virtualHostedBucket && (o += "/" + e2.virtualHostedBucket), o += r2, i2) {
        var s = [];
        n.util.arrayEach.call(this, i2.split("&"), function(e3) {
          var t3 = e3.split("=")[0], r3 = e3.split("=")[1];
          if (this.subResources[t3] || this.responseHeaders[t3]) {
            var n2 = {name: t3};
            void 0 !== r3 && (this.subResources[t3] ? n2.value = r3 : n2.value = decodeURIComponent(r3)), s.push(n2);
          }
        }), s.sort(function(e3, t3) {
          return e3.name < t3.name ? -1 : 1;
        }), s.length && (i2 = [], n.util.arrayEach(s, function(e3) {
          void 0 === e3.value ? i2.push(e3.name) : i2.push(e3.name + "=" + e3.value);
        }), o += "?" + i2.join("&"));
      }
      return o;
    }, sign: function(e2, t2) {
      return n.util.crypto.hmac(e2, t2, "base64", "sha1");
    }}), t.exports = n.Signers.S3;
  }, {"../core": 39}], 109: [function(e, t, r) {
    function n(e2) {
      var t2 = e2.httpRequest.headers[a], r2 = e2.service.getSignerClass(e2);
      if (delete e2.httpRequest.headers["User-Agent"], delete e2.httpRequest.headers["X-Amz-User-Agent"], r2 === o.Signers.V4) {
        if (t2 > 604800)
          throw o.util.error(new Error(), {code: "InvalidExpiryTime", message: "Presigning does not support expiry time greater than a week with SigV4 signing.", retryable: false});
        e2.httpRequest.headers[a] = t2;
      } else {
        if (r2 !== o.Signers.S3)
          throw o.util.error(new Error(), {message: "Presigning only supports S3 or SigV4 signing.", code: "UnsupportedSigner", retryable: false});
        var n2 = e2.service ? e2.service.getSkewCorrectedDate() : o.util.date.getDate();
        e2.httpRequest.headers[a] = parseInt(o.util.date.unixTimestamp(n2) + t2, 10).toString();
      }
    }
    function i(e2) {
      var t2 = e2.httpRequest.endpoint, r2 = o.util.urlParse(e2.httpRequest.path), n2 = {};
      r2.search && (n2 = o.util.queryStringParse(r2.search.substr(1)));
      var i2 = e2.httpRequest.headers.Authorization.split(" ");
      if ("AWS" === i2[0])
        i2 = i2[1].split(":"), n2.Signature = i2.pop(), n2.AWSAccessKeyId = i2.join(":"), o.util.each(e2.httpRequest.headers, function(e3, t3) {
          e3 === a && (e3 = "Expires"), 0 === e3.indexOf("x-amz-meta-") && (delete n2[e3], e3 = e3.toLowerCase()), n2[e3] = t3;
        }), delete e2.httpRequest.headers[a], delete n2.Authorization, delete n2.Host;
      else if ("AWS4-HMAC-SHA256" === i2[0]) {
        i2.shift();
        var s2 = i2.join(" "), u = s2.match(/Signature=(.*?)(?:,|\s|\r?\n|$)/)[1];
        n2["X-Amz-Signature"] = u, delete n2.Expires;
      }
      t2.pathname = r2.pathname, t2.search = o.util.queryParamsToString(n2);
    }
    var o = e("../core"), s = o.util.inherit, a = "presigned-expires";
    o.Signers.Presign = s({sign: function(e2, t2, r2) {
      if (e2.httpRequest.headers[a] = t2 || 3600, e2.on("build", n), e2.on("sign", i), e2.removeListener("afterBuild", o.EventListeners.Core.SET_CONTENT_LENGTH), e2.removeListener("afterBuild", o.EventListeners.Core.COMPUTE_SHA256), e2.emit("beforePresign", [e2]), !r2) {
        if (e2.build(), e2.response.error)
          throw e2.response.error;
        return o.util.urlFormat(e2.httpRequest.endpoint);
      }
      e2.build(function() {
        this.response.error ? r2(this.response.error) : r2(null, o.util.urlFormat(e2.httpRequest.endpoint));
      });
    }}), t.exports = o.Signers.Presign;
  }, {"../core": 39}], 89: [function(e, t, r) {
    (function(r2) {
      var n = e("./core"), i = e("./model/api"), o = e("./region_config"), s = n.util.inherit, a = 0;
      n.Service = s({constructor: function(e2) {
        if (!this.loadServiceClass)
          throw n.util.error(new Error(), "Service must be constructed with `new' operator");
        var t2 = this.loadServiceClass(e2 || {});
        if (t2) {
          var r3 = n.util.copy(e2), i2 = new t2(e2);
          return Object.defineProperty(i2, "_originalConfig", {get: function() {
            return r3;
          }, enumerable: false, configurable: true}), i2._clientId = ++a, i2;
        }
        this.initialize(e2);
      }, initialize: function(e2) {
        var t2 = n.config[this.serviceIdentifier];
        if (this.config = new n.Config(n.config), t2 && this.config.update(t2, true), e2 && this.config.update(e2, true), this.validateService(), this.config.endpoint || o.configureEndpoint(this), this.config.endpoint = this.endpointFromTemplate(this.config.endpoint), this.setEndpoint(this.config.endpoint), n.SequentialExecutor.call(this), n.Service.addDefaultMonitoringListeners(this), (this.config.clientSideMonitoring || n.Service._clientSideMonitoring) && this.publisher) {
          var i2 = this.publisher;
          this.addNamedListener("PUBLISH_API_CALL", "apiCall", function(e3) {
            r2.nextTick(function() {
              i2.eventHandler(e3);
            });
          }), this.addNamedListener("PUBLISH_API_ATTEMPT", "apiCallAttempt", function(e3) {
            r2.nextTick(function() {
              i2.eventHandler(e3);
            });
          });
        }
      }, validateService: function() {
      }, loadServiceClass: function(e2) {
        var t2 = e2;
        if (n.util.isEmpty(this.api)) {
          if (t2.apiConfig)
            return n.Service.defineServiceApi(this.constructor, t2.apiConfig);
          if (this.constructor.services) {
            t2 = new n.Config(n.config), t2.update(e2, true);
            var r3 = t2.apiVersions[this.constructor.serviceIdentifier];
            return r3 = r3 || t2.apiVersion, this.getLatestServiceClass(r3);
          }
          return null;
        }
        return null;
      }, getLatestServiceClass: function(e2) {
        return e2 = this.getLatestServiceVersion(e2), null === this.constructor.services[e2] && n.Service.defineServiceApi(this.constructor, e2), this.constructor.services[e2];
      }, getLatestServiceVersion: function(e2) {
        if (!this.constructor.services || 0 === this.constructor.services.length)
          throw new Error("No services defined on " + this.constructor.serviceIdentifier);
        if (e2 ? n.util.isType(e2, Date) && (e2 = n.util.date.iso8601(e2).split("T")[0]) : e2 = "latest", Object.hasOwnProperty(this.constructor.services, e2))
          return e2;
        for (var t2 = Object.keys(this.constructor.services).sort(), r3 = null, i2 = t2.length - 1; i2 >= 0; i2--)
          if ("*" !== t2[i2][t2[i2].length - 1] && (r3 = t2[i2]), t2[i2].substr(0, 10) <= e2)
            return r3;
        throw new Error("Could not find " + this.constructor.serviceIdentifier + " API to satisfy version constraint `" + e2 + "'");
      }, api: {}, defaultRetryCount: 3, customizeRequests: function(e2) {
        if (e2) {
          if ("function" != typeof e2)
            throw new Error("Invalid callback type '" + typeof e2 + "' provided in customizeRequests");
          this.customRequestHandler = e2;
        } else
          this.customRequestHandler = null;
      }, makeRequest: function(e2, t2, r3) {
        if ("function" == typeof t2 && (r3 = t2, t2 = null), t2 = t2 || {}, this.config.params) {
          var i2 = this.api.operations[e2];
          i2 && (t2 = n.util.copy(t2), n.util.each(this.config.params, function(e3, r4) {
            i2.input.members[e3] && (void 0 !== t2[e3] && null !== t2[e3] || (t2[e3] = r4));
          }));
        }
        var o2 = new n.Request(this, e2, t2);
        return this.addAllRequestListeners(o2), this.attachMonitoringEmitter(o2), r3 && o2.send(r3), o2;
      }, makeUnauthenticatedRequest: function(e2, t2, r3) {
        "function" == typeof t2 && (r3 = t2, t2 = {});
        var n2 = this.makeRequest(e2, t2).toUnauthenticated();
        return r3 ? n2.send(r3) : n2;
      }, waitFor: function(e2, t2, r3) {
        return new n.ResourceWaiter(this, e2).wait(t2, r3);
      }, addAllRequestListeners: function(e2) {
        for (var t2 = [n.events, n.EventListeners.Core, this.serviceInterface(), n.EventListeners.CorePost], r3 = 0; r3 < t2.length; r3++)
          t2[r3] && e2.addListeners(t2[r3]);
        this.config.paramValidation || e2.removeListener("validate", n.EventListeners.Core.VALIDATE_PARAMETERS), this.config.logger && e2.addListeners(n.EventListeners.Logger), this.setupRequestListeners(e2), "function" == typeof this.constructor.prototype.customRequestHandler && this.constructor.prototype.customRequestHandler(e2), Object.prototype.hasOwnProperty.call(this, "customRequestHandler") && "function" == typeof this.customRequestHandler && this.customRequestHandler(e2);
      }, apiCallEvent: function(e2) {
        var t2 = e2.service.api.operations[e2.operation], r3 = {Type: "ApiCall", Api: t2 ? t2.name : e2.operation, Version: 1, Service: e2.service.api.serviceId || e2.service.api.endpointPrefix, Region: e2.httpRequest.region, MaxRetriesExceeded: 0, UserAgent: e2.httpRequest.getUserAgent()}, n2 = e2.response;
        if (n2.httpResponse.statusCode && (r3.FinalHttpStatusCode = n2.httpResponse.statusCode), n2.error) {
          var i2 = n2.error;
          n2.httpResponse.statusCode > 299 ? (i2.code && (r3.FinalAwsException = i2.code), i2.message && (r3.FinalAwsExceptionMessage = i2.message)) : ((i2.code || i2.name) && (r3.FinalSdkException = i2.code || i2.name), i2.message && (r3.FinalSdkExceptionMessage = i2.message));
        }
        return r3;
      }, apiAttemptEvent: function(e2) {
        var t2 = e2.service.api.operations[e2.operation], r3 = {Type: "ApiCallAttempt", Api: t2 ? t2.name : e2.operation, Version: 1, Service: e2.service.api.serviceId || e2.service.api.endpointPrefix, Fqdn: e2.httpRequest.endpoint.hostname, UserAgent: e2.httpRequest.getUserAgent()}, n2 = e2.response;
        return n2.httpResponse.statusCode && (r3.HttpStatusCode = n2.httpResponse.statusCode), !e2._unAuthenticated && e2.service.config.credentials && e2.service.config.credentials.accessKeyId && (r3.AccessKey = e2.service.config.credentials.accessKeyId), n2.httpResponse.headers ? (e2.httpRequest.headers["x-amz-security-token"] && (r3.SessionToken = e2.httpRequest.headers["x-amz-security-token"]), n2.httpResponse.headers["x-amzn-requestid"] && (r3.XAmznRequestId = n2.httpResponse.headers["x-amzn-requestid"]), n2.httpResponse.headers["x-amz-request-id"] && (r3.XAmzRequestId = n2.httpResponse.headers["x-amz-request-id"]), n2.httpResponse.headers["x-amz-id-2"] && (r3.XAmzId2 = n2.httpResponse.headers["x-amz-id-2"]), r3) : r3;
      }, attemptFailEvent: function(e2) {
        var t2 = this.apiAttemptEvent(e2), r3 = e2.response, n2 = r3.error;
        return r3.httpResponse.statusCode > 299 ? (n2.code && (t2.AwsException = n2.code), n2.message && (t2.AwsExceptionMessage = n2.message)) : ((n2.code || n2.name) && (t2.SdkException = n2.code || n2.name), n2.message && (t2.SdkExceptionMessage = n2.message)), t2;
      }, attachMonitoringEmitter: function(e2) {
        var t2, r3, i2, o2, s2, a2, u = 0, c = this;
        e2.on("validate", function() {
          o2 = n.util.realClock.now(), a2 = Date.now();
        }, true), e2.on("sign", function() {
          r3 = n.util.realClock.now(), t2 = Date.now(), s2 = e2.httpRequest.region, u++;
        }, true), e2.on("validateResponse", function() {
          i2 = Math.round(n.util.realClock.now() - r3);
        }), e2.addNamedListener("API_CALL_ATTEMPT", "success", function() {
          var r4 = c.apiAttemptEvent(e2);
          r4.Timestamp = t2, r4.AttemptLatency = i2 >= 0 ? i2 : 0, r4.Region = s2, c.emit("apiCallAttempt", [r4]);
        }), e2.addNamedListener("API_CALL_ATTEMPT_RETRY", "retry", function() {
          var o3 = c.attemptFailEvent(e2);
          o3.Timestamp = t2, i2 = i2 || Math.round(n.util.realClock.now() - r3), o3.AttemptLatency = i2 >= 0 ? i2 : 0, o3.Region = s2, c.emit("apiCallAttempt", [o3]);
        }), e2.addNamedListener("API_CALL", "complete", function() {
          var t3 = c.apiCallEvent(e2);
          if (t3.AttemptCount = u, !(t3.AttemptCount <= 0)) {
            t3.Timestamp = a2;
            var r4 = Math.round(n.util.realClock.now() - o2);
            t3.Latency = r4 >= 0 ? r4 : 0;
            var i3 = e2.response;
            i3.error && i3.error.retryable && "number" == typeof i3.retryCount && "number" == typeof i3.maxRetries && i3.retryCount >= i3.maxRetries && (t3.MaxRetriesExceeded = 1), c.emit("apiCall", [t3]);
          }
        });
      }, setupRequestListeners: function(e2) {
      }, getSignerClass: function(e2) {
        var t2, r3 = null, i2 = "";
        return e2 && (r3 = (e2.service.api.operations || {})[e2.operation] || null, i2 = r3 ? r3.authtype : ""), t2 = this.config.signatureVersion ? this.config.signatureVersion : "v4" === i2 || "v4-unsigned-body" === i2 ? "v4" : this.api.signatureVersion, n.Signers.RequestSigner.getVersion(t2);
      }, serviceInterface: function() {
        switch (this.api.protocol) {
          case "ec2":
          case "query":
            return n.EventListeners.Query;
          case "json":
            return n.EventListeners.Json;
          case "rest-json":
            return n.EventListeners.RestJson;
          case "rest-xml":
            return n.EventListeners.RestXml;
        }
        if (this.api.protocol)
          throw new Error("Invalid service `protocol' " + this.api.protocol + " in API config");
      }, successfulResponse: function(e2) {
        return e2.httpResponse.statusCode < 300;
      }, numRetries: function() {
        return void 0 !== this.config.maxRetries ? this.config.maxRetries : this.defaultRetryCount;
      }, retryDelays: function(e2, t2) {
        return n.util.calculateRetryDelay(e2, this.config.retryDelayOptions, t2);
      }, retryableError: function(e2) {
        return !!this.timeoutError(e2) || (!!this.networkingError(e2) || (!!this.expiredCredentialsError(e2) || (!!this.throttledError(e2) || e2.statusCode >= 500)));
      }, networkingError: function(e2) {
        return "NetworkingError" === e2.code;
      }, timeoutError: function(e2) {
        return "TimeoutError" === e2.code;
      }, expiredCredentialsError: function(e2) {
        return "ExpiredTokenException" === e2.code;
      }, clockSkewError: function(e2) {
        switch (e2.code) {
          case "RequestTimeTooSkewed":
          case "RequestExpired":
          case "InvalidSignatureException":
          case "SignatureDoesNotMatch":
          case "AuthFailure":
          case "RequestInTheFuture":
            return true;
          default:
            return false;
        }
      }, getSkewCorrectedDate: function() {
        return new Date(Date.now() + this.config.systemClockOffset);
      }, applyClockOffset: function(e2) {
        e2 && (this.config.systemClockOffset = e2 - Date.now());
      }, isClockSkewed: function(e2) {
        if (e2)
          return Math.abs(this.getSkewCorrectedDate().getTime() - e2) >= 3e5;
      }, throttledError: function(e2) {
        if (429 === e2.statusCode)
          return true;
        switch (e2.code) {
          case "ProvisionedThroughputExceededException":
          case "Throttling":
          case "ThrottlingException":
          case "RequestLimitExceeded":
          case "RequestThrottled":
          case "RequestThrottledException":
          case "TooManyRequestsException":
          case "TransactionInProgressException":
          case "EC2ThrottledException":
            return true;
          default:
            return false;
        }
      }, endpointFromTemplate: function(e2) {
        if ("string" != typeof e2)
          return e2;
        var t2 = e2;
        return t2 = t2.replace(/\{service\}/g, this.api.endpointPrefix), t2 = t2.replace(/\{region\}/g, this.config.region), t2 = t2.replace(/\{scheme\}/g, this.config.sslEnabled ? "https" : "http");
      }, setEndpoint: function(e2) {
        this.endpoint = new n.Endpoint(e2, this.config);
      }, paginationConfig: function(e2, t2) {
        var r3 = this.api.operations[e2].paginator;
        if (!r3) {
          if (t2) {
            var i2 = new Error();
            throw n.util.error(i2, "No pagination configuration for " + e2);
          }
          return null;
        }
        return r3;
      }}), n.util.update(n.Service, {
        defineMethods: function(e2) {
          n.util.each(e2.prototype.api.operations, function(t2) {
            e2.prototype[t2] || ("none" === e2.prototype.api.operations[t2].authtype ? e2.prototype[t2] = function(e3, r3) {
              return this.makeUnauthenticatedRequest(t2, e3, r3);
            } : e2.prototype[t2] = function(e3, r3) {
              return this.makeRequest(t2, e3, r3);
            });
          });
        },
        defineService: function(e2, t2, r3) {
          n.Service._serviceMap[e2] = true, Array.isArray(t2) || (r3 = t2, t2 = []);
          var i2 = s(n.Service, r3 || {});
          if ("string" == typeof e2) {
            n.Service.addVersions(i2, t2);
            var o2 = i2.serviceIdentifier || e2;
            i2.serviceIdentifier = o2;
          } else
            i2.prototype.api = e2, n.Service.defineMethods(i2);
          if (n.SequentialExecutor.call(this.prototype), !this.prototype.publisher && n.util.clientSideMonitoring) {
            var a2 = n.util.clientSideMonitoring.Publisher, u = n.util.clientSideMonitoring.configProvider, c = u();
            this.prototype.publisher = new a2(c), c.enabled && (n.Service._clientSideMonitoring = true);
          }
          return n.SequentialExecutor.call(i2.prototype), n.Service.addDefaultMonitoringListeners(i2.prototype), i2;
        },
        addVersions: function(e2, t2) {
          Array.isArray(t2) || (t2 = [t2]), e2.services = e2.services || {};
          for (var r3 = 0; r3 < t2.length; r3++)
            void 0 === e2.services[t2[r3]] && (e2.services[t2[r3]] = null);
          e2.apiVersions = Object.keys(e2.services).sort();
        },
        defineServiceApi: function(e2, t2, r3) {
          function o2(t3) {
            t3.isApi ? a2.prototype.api = t3 : a2.prototype.api = new i(t3, {serviceIdentifier: e2.serviceIdentifier});
          }
          var a2 = s(e2, {serviceIdentifier: e2.serviceIdentifier});
          if ("string" == typeof t2) {
            if (r3)
              o2(r3);
            else
              try {
                o2(n.apiLoader(e2.serviceIdentifier, t2));
              } catch (r4) {
                throw n.util.error(r4, {message: "Could not find API configuration " + e2.serviceIdentifier + "-" + t2});
              }
            Object.prototype.hasOwnProperty.call(e2.services, t2) || (e2.apiVersions = e2.apiVersions.concat(t2).sort()), e2.services[t2] = a2;
          } else
            o2(t2);
          return n.Service.defineMethods(a2), a2;
        },
        hasService: function(e2) {
          return Object.prototype.hasOwnProperty.call(n.Service._serviceMap, e2);
        },
        addDefaultMonitoringListeners: function(e2) {
          e2.addNamedListener("MONITOR_EVENTS_BUBBLE", "apiCallAttempt", function(t2) {
            var r3 = Object.getPrototypeOf(e2);
            r3._events && r3.emit("apiCallAttempt", [t2]);
          }), e2.addNamedListener("CALL_EVENTS_BUBBLE", "apiCall", function(t2) {
            var r3 = Object.getPrototypeOf(e2);
            r3._events && r3.emit("apiCall", [t2]);
          });
        },
        _serviceMap: {}
      }), n.util.mixin(n.Service, n.SequentialExecutor), t.exports = n.Service;
    }).call(this, e("_process"));
  }, {"./core": 39, "./model/api": 65, "./region_config": 82, _process: 8}], 82: [function(e, t, r) {
    function n(e2) {
      if (!e2)
        return null;
      var t2 = e2.split("-");
      return t2.length < 3 ? null : t2.slice(0, t2.length - 2).join("-") + "-*";
    }
    function i(e2) {
      var t2 = e2.config.region, r2 = n(t2), i2 = e2.api.endpointPrefix;
      return [[t2, i2], [r2, i2], [t2, "*"], [r2, "*"], ["*", i2], ["*", "*"]].map(function(e3) {
        return e3[0] && e3[1] ? e3.join("/") : null;
      });
    }
    function o(e2, t2) {
      u.each(t2, function(t3, r2) {
        "globalEndpoint" !== t3 && (void 0 !== e2.config[t3] && null !== e2.config[t3] || (e2.config[t3] = r2));
      });
    }
    function s(e2) {
      for (var t2 = i(e2), r2 = 0; r2 < t2.length; r2++) {
        var n2 = t2[r2];
        if (n2 && Object.prototype.hasOwnProperty.call(c.rules, n2)) {
          var s2 = c.rules[n2];
          return "string" == typeof s2 && (s2 = c.patterns[s2]), e2.config.useDualstack && u.isDualstackAvailable(e2) && (s2 = u.copy(s2), s2.endpoint = s2.endpoint.replace(/{service}\.({region}\.)?/, "{service}.dualstack.{region}.")), e2.isGlobalEndpoint = !!s2.globalEndpoint, s2.signingRegion && (e2.signingRegion = s2.signingRegion), s2.signatureVersion || (s2.signatureVersion = "v4"), void o(e2, s2);
        }
      }
    }
    function a(e2) {
      for (var t2 = {"^(us|eu|ap|sa|ca|me)\\-\\w+\\-\\d+$": "amazonaws.com", "^cn\\-\\w+\\-\\d+$": "amazonaws.com.cn", "^us\\-gov\\-\\w+\\-\\d+$": "amazonaws.com", "^us\\-iso\\-\\w+\\-\\d+$": "c2s.ic.gov", "^us\\-isob\\-\\w+\\-\\d+$": "sc2s.sgov.gov"}, r2 = Object.keys(t2), n2 = 0; n2 < r2.length; n2++) {
        var i2 = RegExp(r2[n2]), o2 = t2[r2[n2]];
        if (i2.test(e2))
          return o2;
      }
      return "amazonaws.com";
    }
    var u = e("./util"), c = e("./region_config_data.json");
    t.exports = {configureEndpoint: s, getEndpointSuffix: a};
  }, {"./region_config_data.json": 83, "./util": 118}], 83: [function(e, t, r) {
    t.exports = {rules: {"*/*": {endpoint: "{service}.{region}.amazonaws.com"}, "cn-*/*": {endpoint: "{service}.{region}.amazonaws.com.cn"}, "us-iso-*/*": {endpoint: "{service}.{region}.c2s.ic.gov"}, "us-isob-*/*": {endpoint: "{service}.{region}.sc2s.sgov.gov"}, "*/budgets": "globalSSL", "*/cloudfront": "globalSSL", "*/sts": "globalSSL", "*/importexport": {endpoint: "{service}.amazonaws.com", signatureVersion: "v2", globalEndpoint: true}, "*/route53": "globalSSL", "cn-*/route53": {endpoint: "{service}.amazonaws.com.cn", globalEndpoint: true, signingRegion: "cn-northwest-1"}, "us-gov-*/route53": "globalGovCloud", "*/waf": "globalSSL", "*/iam": "globalSSL", "cn-*/iam": {endpoint: "{service}.cn-north-1.amazonaws.com.cn", globalEndpoint: true, signingRegion: "cn-north-1"}, "us-gov-*/iam": "globalGovCloud", "us-gov-*/sts": {endpoint: "{service}.{region}.amazonaws.com"}, "us-gov-west-1/s3": "s3signature", "us-west-1/s3": "s3signature", "us-west-2/s3": "s3signature", "eu-west-1/s3": "s3signature", "ap-southeast-1/s3": "s3signature", "ap-southeast-2/s3": "s3signature", "ap-northeast-1/s3": "s3signature", "sa-east-1/s3": "s3signature", "us-east-1/s3": {endpoint: "{service}.amazonaws.com", signatureVersion: "s3"}, "us-east-1/sdb": {endpoint: "{service}.amazonaws.com", signatureVersion: "v2"}, "*/sdb": {endpoint: "{service}.{region}.amazonaws.com", signatureVersion: "v2"}}, patterns: {globalSSL: {endpoint: "https://{service}.amazonaws.com", globalEndpoint: true, signingRegion: "us-east-1"}, globalGovCloud: {endpoint: "{service}.us-gov.amazonaws.com", globalEndpoint: true, signingRegion: "us-gov-west-1"}, s3signature: {endpoint: "{service}.{region}.amazonaws.com", signatureVersion: "s3"}}};
  }, {}], 86: [function(e, t, r) {
    var n = e("./core"), i = n.util.inherit, o = e("jmespath");
    n.Response = i({constructor: function(e2) {
      this.request = e2, this.data = null, this.error = null, this.retryCount = 0, this.redirectCount = 0, this.httpResponse = new n.HttpResponse(), e2 && (this.maxRetries = e2.service.numRetries(), this.maxRedirects = e2.service.config.maxRedirects);
    }, nextPage: function(e2) {
      var t2, r2 = this.request.service, i2 = this.request.operation;
      try {
        t2 = r2.paginationConfig(i2, true);
      } catch (e3) {
        this.error = e3;
      }
      if (!this.hasNextPage()) {
        if (e2)
          e2(this.error, null);
        else if (this.error)
          throw this.error;
        return null;
      }
      var o2 = n.util.copy(this.request.params);
      if (this.nextPageTokens) {
        var s = t2.inputToken;
        "string" == typeof s && (s = [s]);
        for (var a = 0; a < s.length; a++)
          o2[s[a]] = this.nextPageTokens[a];
        return r2.makeRequest(this.request.operation, o2, e2);
      }
      return e2 ? e2(null, null) : null;
    }, hasNextPage: function() {
      return this.cacheNextPageTokens(), !!this.nextPageTokens || void 0 === this.nextPageTokens && void 0;
    }, cacheNextPageTokens: function() {
      if (Object.prototype.hasOwnProperty.call(this, "nextPageTokens"))
        return this.nextPageTokens;
      this.nextPageTokens = void 0;
      var e2 = this.request.service.paginationConfig(this.request.operation);
      if (!e2)
        return this.nextPageTokens;
      if (this.nextPageTokens = null, e2.moreResults && !o.search(this.data, e2.moreResults))
        return this.nextPageTokens;
      var t2 = e2.outputToken;
      return "string" == typeof t2 && (t2 = [t2]), n.util.arrayEach.call(this, t2, function(e3) {
        var t3 = o.search(this.data, e3);
        t3 && (this.nextPageTokens = this.nextPageTokens || [], this.nextPageTokens.push(t3));
      }), this.nextPageTokens;
    }});
  }, {"./core": 39, jmespath: 7}], 85: [function(e, t, r) {
    function n(e2) {
      var t2 = e2.request._waiter, r2 = t2.config.acceptors, n2 = false, i2 = "retry";
      r2.forEach(function(r3) {
        if (!n2) {
          var o2 = t2.matchers[r3.matcher];
          o2 && o2(e2, r3.expected, r3.argument) && (n2 = true, i2 = r3.state);
        }
      }), !n2 && e2.error && (i2 = "failure"), "success" === i2 ? t2.setSuccess(e2) : t2.setError(e2, "retry" === i2);
    }
    var i = e("./core"), o = i.util.inherit, s = e("jmespath");
    i.ResourceWaiter = o({constructor: function(e2, t2) {
      this.service = e2, this.state = t2, this.loadWaiterConfig(this.state);
    }, service: null, state: null, config: null, matchers: {path: function(e2, t2, r2) {
      try {
        var n2 = s.search(e2.data, r2);
      } catch (e3) {
        return false;
      }
      return s.strictDeepEqual(n2, t2);
    }, pathAll: function(e2, t2, r2) {
      try {
        var n2 = s.search(e2.data, r2);
      } catch (e3) {
        return false;
      }
      Array.isArray(n2) || (n2 = [n2]);
      var i2 = n2.length;
      if (!i2)
        return false;
      for (var o2 = 0; o2 < i2; o2++)
        if (!s.strictDeepEqual(n2[o2], t2))
          return false;
      return true;
    }, pathAny: function(e2, t2, r2) {
      try {
        var n2 = s.search(e2.data, r2);
      } catch (e3) {
        return false;
      }
      Array.isArray(n2) || (n2 = [n2]);
      for (var i2 = n2.length, o2 = 0; o2 < i2; o2++)
        if (s.strictDeepEqual(n2[o2], t2))
          return true;
      return false;
    }, status: function(e2, t2) {
      var r2 = e2.httpResponse.statusCode;
      return "number" == typeof r2 && r2 === t2;
    }, error: function(e2, t2) {
      return "string" == typeof t2 && e2.error ? t2 === e2.error.code : t2 === !!e2.error;
    }}, listeners: new i.SequentialExecutor().addNamedListeners(function(e2) {
      e2("RETRY_CHECK", "retry", function(e3) {
        var t2 = e3.request._waiter;
        e3.error && "ResourceNotReady" === e3.error.code && (e3.error.retryDelay = 1e3 * (t2.config.delay || 0));
      }), e2("CHECK_OUTPUT", "extractData", n), e2("CHECK_ERROR", "extractError", n);
    }), wait: function(e2, t2) {
      "function" == typeof e2 && (t2 = e2, e2 = void 0), e2 && e2.$waiter && (e2 = i.util.copy(e2), "number" == typeof e2.$waiter.delay && (this.config.delay = e2.$waiter.delay), "number" == typeof e2.$waiter.maxAttempts && (this.config.maxAttempts = e2.$waiter.maxAttempts), delete e2.$waiter);
      var r2 = this.service.makeRequest(this.config.operation, e2);
      return r2._waiter = this, r2.response.maxRetries = this.config.maxAttempts, r2.addListeners(this.listeners), t2 && r2.send(t2), r2;
    }, setSuccess: function(e2) {
      e2.error = null, e2.data = e2.data || {}, e2.request.removeAllListeners("extractData");
    }, setError: function(e2, t2) {
      e2.data = null, e2.error = i.util.error(e2.error || new Error(), {code: "ResourceNotReady", message: "Resource is not in the state " + this.state, retryable: t2});
    }, loadWaiterConfig: function(e2) {
      if (!this.service.api.waiters[e2])
        throw new i.util.error(new Error(), {code: "StateNotFoundError", message: "State " + e2 + " not found."});
      this.config = i.util.copy(this.service.api.waiters[e2]);
    }});
  }, {"./core": 39, jmespath: 7}], 84: [function(e, t, r) {
    (function(t2) {
      function r2(e2) {
        return Object.prototype.hasOwnProperty.call(u, e2._asm.currentState);
      }
      var n = e("./core"), i = e("./state_machine"), o = n.util.inherit, s = n.util.domain, a = e("jmespath"), u = {success: 1, error: 1, complete: 1}, c = new i();
      c.setupStates = function() {
        var e2 = function(e3, t3) {
          var n2 = this;
          n2._haltHandlersOnError = false, n2.emit(n2._asm.currentState, function(e4) {
            if (e4)
              if (r2(n2)) {
                if (!(s && n2.domain instanceof s.Domain))
                  throw e4;
                e4.domainEmitter = n2, e4.domain = n2.domain, e4.domainThrown = false, n2.domain.emit("error", e4);
              } else
                n2.response.error = e4, t3(e4);
            else
              t3(n2.response.error);
          });
        };
        this.addState("validate", "build", "error", e2), this.addState("build", "afterBuild", "restart", e2), this.addState("afterBuild", "sign", "restart", e2), this.addState("sign", "send", "retry", e2), this.addState("retry", "afterRetry", "afterRetry", e2), this.addState("afterRetry", "sign", "error", e2), this.addState("send", "validateResponse", "retry", e2), this.addState("validateResponse", "extractData", "extractError", e2), this.addState("extractError", "extractData", "retry", e2), this.addState("extractData", "success", "retry", e2), this.addState("restart", "build", "error", e2), this.addState("success", "complete", "complete", e2), this.addState("error", "complete", "complete", e2), this.addState("complete", null, null, e2);
      }, c.setupStates(), n.Request = o({constructor: function(e2, t3, r3) {
        var o2 = e2.endpoint, a2 = e2.config.region, u2 = e2.config.customUserAgent;
        e2.isGlobalEndpoint && (a2 = e2.signingRegion ? e2.signingRegion : "us-east-1"), this.domain = s && s.active, this.service = e2, this.operation = t3, this.params = r3 || {}, this.httpRequest = new n.HttpRequest(o2, a2), this.httpRequest.appendToUserAgent(u2), this.startTime = e2.getSkewCorrectedDate(), this.response = new n.Response(this), this._asm = new i(c.states, "validate"), this._haltHandlersOnError = false, n.SequentialExecutor.call(this), this.emit = this.emitEvent;
      }, send: function(e2) {
        return e2 && (this.httpRequest.appendToUserAgent("callback"), this.on("complete", function(t3) {
          e2.call(t3, t3.error, t3.data);
        })), this.runTo(), this.response;
      }, build: function(e2) {
        return this.runTo("send", e2);
      }, runTo: function(e2, t3) {
        return this._asm.runTo(e2, t3, this), this;
      }, abort: function() {
        return this.removeAllListeners("validateResponse"), this.removeAllListeners("extractError"), this.on("validateResponse", function(e2) {
          e2.error = n.util.error(new Error("Request aborted by user"), {code: "RequestAbortedError", retryable: false});
        }), this.httpRequest.stream && !this.httpRequest.stream.didCallback && (this.httpRequest.stream.abort(), this.httpRequest._abortCallback ? this.httpRequest._abortCallback() : this.removeAllListeners("send")), this;
      }, eachPage: function(e2) {
        function t3(r3) {
          e2.call(r3, r3.error, r3.data, function(i2) {
            false !== i2 && (r3.hasNextPage() ? r3.nextPage().on("complete", t3).send() : e2.call(r3, null, null, n.util.fn.noop));
          });
        }
        e2 = n.util.fn.makeAsync(e2, 3), this.on("complete", t3).send();
      }, eachItem: function(e2) {
        function t3(t4, i2) {
          if (t4)
            return e2(t4, null);
          if (null === i2)
            return e2(null, null);
          var o2 = r3.service.paginationConfig(r3.operation), s2 = o2.resultKey;
          Array.isArray(s2) && (s2 = s2[0]);
          var u2 = a.search(i2, s2), c2 = true;
          return n.util.arrayEach(u2, function(t5) {
            if (false === (c2 = e2(null, t5)))
              return n.util.abort;
          }), c2;
        }
        var r3 = this;
        this.eachPage(t3);
      }, isPageable: function() {
        return !!this.service.paginationConfig(this.operation);
      }, createReadStream: function() {
        var e2 = n.util.stream, r3 = this, i2 = null;
        return 2 === n.HttpClient.streamsApiVersion ? (i2 = new e2.PassThrough(), t2.nextTick(function() {
          r3.send();
        })) : (i2 = new e2.Stream(), i2.readable = true, i2.sent = false, i2.on("newListener", function(e3) {
          i2.sent || "data" !== e3 || (i2.sent = true, t2.nextTick(function() {
            r3.send();
          }));
        })), this.on("error", function(e3) {
          i2.emit("error", e3);
        }), this.on("httpHeaders", function(t3, o2, s2) {
          if (t3 < 300) {
            r3.removeListener("httpData", n.EventListeners.Core.HTTP_DATA), r3.removeListener("httpError", n.EventListeners.Core.HTTP_ERROR), r3.on("httpError", function(e3) {
              s2.error = e3, s2.error.retryable = false;
            });
            var a2, u2 = false;
            if ("HEAD" !== r3.httpRequest.method && (a2 = parseInt(o2["content-length"], 10)), void 0 !== a2 && !isNaN(a2) && a2 >= 0) {
              u2 = true;
              var c2 = 0;
            }
            var l = function() {
              u2 && c2 !== a2 ? i2.emit("error", n.util.error(new Error("Stream content length mismatch. Received " + c2 + " of " + a2 + " bytes."), {code: "StreamContentLengthMismatch"})) : 2 === n.HttpClient.streamsApiVersion ? i2.end() : i2.emit("end");
            }, h = s2.httpResponse.createUnbufferedStream();
            if (2 === n.HttpClient.streamsApiVersion)
              if (u2) {
                var p = new e2.PassThrough();
                p._write = function(t4) {
                  return t4 && t4.length && (c2 += t4.length), e2.PassThrough.prototype._write.apply(this, arguments);
                }, p.on("end", l), i2.on("error", function(e3) {
                  u2 = false, h.unpipe(p), p.emit("end"), p.end();
                }), h.pipe(p).pipe(i2, {end: false});
              } else
                h.pipe(i2);
            else
              u2 && h.on("data", function(e3) {
                e3 && e3.length && (c2 += e3.length);
              }), h.on("data", function(e3) {
                i2.emit("data", e3);
              }), h.on("end", l);
            h.on("error", function(e3) {
              u2 = false, i2.emit("error", e3);
            });
          }
        }), i2;
      }, emitEvent: function(e2, t3, r3) {
        "function" == typeof t3 && (r3 = t3, t3 = null), r3 || (r3 = function() {
        }), t3 || (t3 = this.eventParameters(e2, this.response)), n.SequentialExecutor.prototype.emit.call(this, e2, t3, function(e3) {
          e3 && (this.response.error = e3), r3.call(this, e3);
        });
      }, eventParameters: function(e2) {
        switch (e2) {
          case "restart":
          case "validate":
          case "sign":
          case "build":
          case "afterValidate":
          case "afterBuild":
            return [this];
          case "error":
            return [this.response.error, this.response];
          default:
            return [this.response];
        }
      }, presign: function(e2, t3) {
        return t3 || "function" != typeof e2 || (t3 = e2, e2 = null), new n.Signers.Presign().sign(this.toGet(), e2, t3);
      }, isPresigned: function() {
        return Object.prototype.hasOwnProperty.call(this.httpRequest.headers, "presigned-expires");
      }, toUnauthenticated: function() {
        return this._unAuthenticated = true, this.removeListener("validate", n.EventListeners.Core.VALIDATE_CREDENTIALS), this.removeListener("sign", n.EventListeners.Core.SIGN), this;
      }, toGet: function() {
        return "query" !== this.service.api.protocol && "ec2" !== this.service.api.protocol || (this.removeListener("build", this.buildAsGet), this.addListener("build", this.buildAsGet)), this;
      }, buildAsGet: function(e2) {
        e2.httpRequest.method = "GET", e2.httpRequest.path = e2.service.endpoint.path + "?" + e2.httpRequest.body, e2.httpRequest.body = "", delete e2.httpRequest.headers["Content-Length"], delete e2.httpRequest.headers["Content-Type"];
      }, haltHandlersOnError: function() {
        this._haltHandlersOnError = true;
      }}), n.Request.addPromisesToClass = function(e2) {
        this.prototype.promise = function() {
          var t3 = this;
          return this.httpRequest.appendToUserAgent("promise"), new e2(function(e3, r3) {
            t3.on("complete", function(t4) {
              t4.error ? r3(t4.error) : e3(Object.defineProperty(t4.data || {}, "$response", {value: t4}));
            }), t3.runTo();
          });
        };
      }, n.Request.deletePromisesFromClass = function() {
        delete this.prototype.promise;
      }, n.util.addPromises(n.Request), n.util.mixin(n.Request, n.SequentialExecutor);
    }).call(this, e("_process"));
  }, {"./core": 39, "./state_machine": 117, _process: 8, jmespath: 7}], 117: [function(e, t, r) {
    function n(e2, t2) {
      this.currentState = t2 || null, this.states = e2 || {};
    }
    n.prototype.runTo = function(e2, t2, r2, n2) {
      "function" == typeof e2 && (n2 = r2, r2 = t2, t2 = e2, e2 = null);
      var i = this, o = i.states[i.currentState];
      o.fn.call(r2 || i, n2, function(n3) {
        if (n3) {
          if (!o.fail)
            return t2 ? t2.call(r2, n3) : null;
          i.currentState = o.fail;
        } else {
          if (!o.accept)
            return t2 ? t2.call(r2) : null;
          i.currentState = o.accept;
        }
        if (i.currentState === e2)
          return t2 ? t2.call(r2, n3) : null;
        i.runTo(e2, t2, r2, n3);
      });
    }, n.prototype.addState = function(e2, t2, r2, n2) {
      return "function" == typeof t2 ? (n2 = t2, t2 = null, r2 = null) : "function" == typeof r2 && (n2 = r2, r2 = null), this.currentState || (this.currentState = e2), this.states[e2] = {accept: t2, fail: r2, fn: n2}, this;
    }, t.exports = n;
  }, {}], 71: [function(e, t, r) {
    var n = e("./core");
    n.ParamValidator = n.util.inherit({constructor: function(e2) {
      true !== e2 && void 0 !== e2 || (e2 = {min: true}), this.validation = e2;
    }, validate: function(e2, t2, r2) {
      if (this.errors = [], this.validateMember(e2, t2 || {}, r2 || "params"), this.errors.length > 1) {
        var i = this.errors.join("\n* ");
        throw i = "There were " + this.errors.length + " validation errors:\n* " + i, n.util.error(new Error(i), {code: "MultipleValidationErrors", errors: this.errors});
      }
      if (1 === this.errors.length)
        throw this.errors[0];
      return true;
    }, fail: function(e2, t2) {
      this.errors.push(n.util.error(new Error(t2), {code: e2}));
    }, validateStructure: function(e2, t2, r2) {
      this.validateType(t2, r2, ["object"], "structure");
      for (var n2, i = 0; e2.required && i < e2.required.length; i++) {
        n2 = e2.required[i];
        var o = t2[n2];
        void 0 !== o && null !== o || this.fail("MissingRequiredParameter", "Missing required key '" + n2 + "' in " + r2);
      }
      for (n2 in t2)
        if (Object.prototype.hasOwnProperty.call(t2, n2)) {
          var s = t2[n2], a = e2.members[n2];
          if (void 0 !== a) {
            var u = [r2, n2].join(".");
            this.validateMember(a, s, u);
          } else
            this.fail("UnexpectedParameter", "Unexpected key '" + n2 + "' found in " + r2);
        }
      return true;
    }, validateMember: function(e2, t2, r2) {
      switch (e2.type) {
        case "structure":
          return this.validateStructure(e2, t2, r2);
        case "list":
          return this.validateList(e2, t2, r2);
        case "map":
          return this.validateMap(e2, t2, r2);
        default:
          return this.validateScalar(e2, t2, r2);
      }
    }, validateList: function(e2, t2, r2) {
      if (this.validateType(t2, r2, [Array])) {
        this.validateRange(e2, t2.length, r2, "list member count");
        for (var n2 = 0; n2 < t2.length; n2++)
          this.validateMember(e2.member, t2[n2], r2 + "[" + n2 + "]");
      }
    }, validateMap: function(e2, t2, r2) {
      if (this.validateType(t2, r2, ["object"], "map")) {
        var n2 = 0;
        for (var i in t2)
          Object.prototype.hasOwnProperty.call(t2, i) && (this.validateMember(e2.key, i, r2 + "[key='" + i + "']"), this.validateMember(e2.value, t2[i], r2 + "['" + i + "']"), n2++);
        this.validateRange(e2, n2, r2, "map member count");
      }
    }, validateScalar: function(e2, t2, r2) {
      switch (e2.type) {
        case null:
        case void 0:
        case "string":
          return this.validateString(e2, t2, r2);
        case "base64":
        case "binary":
          return this.validatePayload(t2, r2);
        case "integer":
        case "float":
          return this.validateNumber(e2, t2, r2);
        case "boolean":
          return this.validateType(t2, r2, ["boolean"]);
        case "timestamp":
          return this.validateType(t2, r2, [Date, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/, "number"], "Date object, ISO-8601 string, or a UNIX timestamp");
        default:
          return this.fail("UnkownType", "Unhandled type " + e2.type + " for " + r2);
      }
    }, validateString: function(e2, t2, r2) {
      var n2 = ["string"];
      e2.isJsonValue && (n2 = n2.concat(["number", "object", "boolean"])), null !== t2 && this.validateType(t2, r2, n2) && (this.validateEnum(e2, t2, r2), this.validateRange(e2, t2.length, r2, "string length"), this.validatePattern(e2, t2, r2), this.validateUri(e2, t2, r2));
    }, validateUri: function(e2, t2, r2) {
      "uri" === e2.location && 0 === t2.length && this.fail("UriParameterError", 'Expected uri parameter to have length >= 1, but found "' + t2 + '" for ' + r2);
    }, validatePattern: function(e2, t2, r2) {
      this.validation.pattern && void 0 !== e2.pattern && (new RegExp(e2.pattern).test(t2) || this.fail("PatternMatchError", 'Provided value "' + t2 + '" does not match regex pattern /' + e2.pattern + "/ for " + r2));
    }, validateRange: function(e2, t2, r2, n2) {
      this.validation.min && void 0 !== e2.min && t2 < e2.min && this.fail("MinRangeError", "Expected " + n2 + " >= " + e2.min + ", but found " + t2 + " for " + r2), this.validation.max && void 0 !== e2.max && t2 > e2.max && this.fail("MaxRangeError", "Expected " + n2 + " <= " + e2.max + ", but found " + t2 + " for " + r2);
    }, validateEnum: function(e2, t2, r2) {
      this.validation.enum && void 0 !== e2.enum && -1 === e2.enum.indexOf(t2) && this.fail("EnumError", "Found string value of " + t2 + ", but expected " + e2.enum.join("|") + " for " + r2);
    }, validateType: function(e2, t2, r2, i) {
      if (null === e2 || void 0 === e2)
        return false;
      for (var o = false, s = 0; s < r2.length; s++) {
        if ("string" == typeof r2[s]) {
          if (typeof e2 === r2[s])
            return true;
        } else if (r2[s] instanceof RegExp) {
          if ((e2 || "").toString().match(r2[s]))
            return true;
        } else {
          if (e2 instanceof r2[s])
            return true;
          if (n.util.isType(e2, r2[s]))
            return true;
          i || o || (r2 = r2.slice()), r2[s] = n.util.typeName(r2[s]);
        }
        o = true;
      }
      var a = i;
      a || (a = r2.join(", ").replace(/,([^,]+)$/, ", or$1"));
      var u = a.match(/^[aeiou]/i) ? "n" : "";
      return this.fail("InvalidParameterType", "Expected " + t2 + " to be a" + u + " " + a), false;
    }, validateNumber: function(e2, t2, r2) {
      if (null !== t2 && void 0 !== t2) {
        if ("string" == typeof t2) {
          var n2 = parseFloat(t2);
          n2.toString() === t2 && (t2 = n2);
        }
        this.validateType(t2, r2, ["number"]) && this.validateRange(e2, t2, r2, "numeric value");
      }
    }, validatePayload: function(e2, t2) {
      if (null !== e2 && void 0 !== e2 && "string" != typeof e2 && (!e2 || "number" != typeof e2.byteLength)) {
        if (n.util.isNode()) {
          var r2 = n.util.stream.Stream;
          if (n.util.Buffer.isBuffer(e2) || e2 instanceof r2)
            return;
        } else if (void 0 !== typeof Blob && e2 instanceof Blob)
          return;
        var i = ["Buffer", "Stream", "File", "Blob", "ArrayBuffer", "DataView"];
        if (e2)
          for (var o = 0; o < i.length; o++) {
            if (n.util.isType(e2, i[o]))
              return;
            if (n.util.typeName(e2.constructor) === i[o])
              return;
          }
        this.fail("InvalidParameterType", "Expected " + t2 + " to be a string, Buffer, Stream, Blob, or typed array object");
      }
    }});
  }, {"./core": 39}], 65: [function(e, t, r) {
    function n(e2, t2) {
      function r2(e3, t3) {
        true === t3.endpointoperation && h(n2, "endpointOperation", l.string.lowerFirst(e3)), t3.endpointdiscovery && !n2.hasRequiredEndpointDiscovery && h(n2, "hasRequiredEndpointDiscovery", true === t3.endpointdiscovery.required);
      }
      var n2 = this;
      e2 = e2 || {}, t2 = t2 || {}, t2.api = this, e2.metadata = e2.metadata || {};
      var f = t2.serviceIdentifier;
      delete t2.serviceIdentifier, h(this, "isApi", true, false), h(this, "apiVersion", e2.metadata.apiVersion), h(this, "endpointPrefix", e2.metadata.endpointPrefix), h(this, "signingName", e2.metadata.signingName), h(this, "globalEndpoint", e2.metadata.globalEndpoint), h(this, "signatureVersion", e2.metadata.signatureVersion), h(this, "jsonVersion", e2.metadata.jsonVersion), h(this, "targetPrefix", e2.metadata.targetPrefix), h(this, "protocol", e2.metadata.protocol), h(this, "timestampFormat", e2.metadata.timestampFormat), h(this, "xmlNamespaceUri", e2.metadata.xmlNamespace), h(this, "abbreviation", e2.metadata.serviceAbbreviation), h(this, "fullName", e2.metadata.serviceFullName), h(this, "serviceId", e2.metadata.serviceId), f && c[f] && h(this, "xmlNoDefaultLists", c[f].xmlNoDefaultLists, false), p(this, "className", function() {
        var t3 = e2.metadata.serviceAbbreviation || e2.metadata.serviceFullName;
        return t3 ? (t3 = t3.replace(/^Amazon|AWS\s*|\(.*|\s+|\W+/g, ""), "ElasticLoadBalancing" === t3 && (t3 = "ELB"), t3) : null;
      }), h(this, "operations", new i(e2.operations, t2, function(e3, r3) {
        return new o(e3, r3, t2);
      }, l.string.lowerFirst, r2)), h(this, "shapes", new i(e2.shapes, t2, function(e3, r3) {
        return s.create(r3, t2);
      })), h(this, "paginators", new i(e2.paginators, t2, function(e3, r3) {
        return new a(e3, r3, t2);
      })), h(this, "waiters", new i(e2.waiters, t2, function(e3, r3) {
        return new u(e3, r3, t2);
      }, l.string.lowerFirst)), t2.documentation && (h(this, "documentation", e2.documentation), h(this, "documentationUrl", e2.documentationUrl));
    }
    var i = e("./collection"), o = e("./operation"), s = e("./shape"), a = e("./paginator"), u = e("./resource_waiter"), c = e("../../apis/metadata.json"), l = e("../util"), h = l.property, p = l.memoizedProperty;
    t.exports = n;
  }, {"../../apis/metadata.json": 26, "../util": 118, "./collection": 66, "./operation": 67, "./paginator": 68, "./resource_waiter": 69, "./shape": 70}], 69: [function(e, t, r) {
    function n(e2, t2, r2) {
      r2 = r2 || {}, o(this, "name", e2), o(this, "api", r2.api, false), t2.operation && o(this, "operation", i.string.lowerFirst(t2.operation));
      var n2 = this;
      ["type", "description", "delay", "maxAttempts", "acceptors"].forEach(function(e3) {
        var r3 = t2[e3];
        r3 && o(n2, e3, r3);
      });
    }
    var i = e("../util"), o = i.property;
    t.exports = n;
  }, {"../util": 118}], 68: [function(e, t, r) {
    function n(e2, t2) {
      i(this, "inputToken", t2.input_token), i(this, "limitKey", t2.limit_key), i(this, "moreResults", t2.more_results), i(this, "outputToken", t2.output_token), i(this, "resultKey", t2.result_key);
    }
    var i = e("../util").property;
    t.exports = n;
  }, {"../util": 118}], 67: [function(e, t, r) {
    function n(e2, t2, r2) {
      var n2 = this;
      r2 = r2 || {}, a(this, "name", t2.name || e2), a(this, "api", r2.api, false), t2.http = t2.http || {}, a(this, "endpoint", t2.endpoint), a(this, "httpMethod", t2.http.method || "POST"), a(this, "httpPath", t2.http.requestUri || "/"), a(this, "authtype", t2.authtype || ""), a(this, "endpointDiscoveryRequired", t2.endpointdiscovery ? t2.endpointdiscovery.required ? "REQUIRED" : "OPTIONAL" : "NULL"), u(this, "input", function() {
        return t2.input ? o.create(t2.input, r2) : new o.create({type: "structure"}, r2);
      }), u(this, "output", function() {
        return t2.output ? o.create(t2.output, r2) : new o.create({type: "structure"}, r2);
      }), u(this, "errors", function() {
        var e3 = [];
        if (!t2.errors)
          return null;
        for (var n3 = 0; n3 < t2.errors.length; n3++)
          e3.push(o.create(t2.errors[n3], r2));
        return e3;
      }), u(this, "paginator", function() {
        return r2.api.paginators[e2];
      }), r2.documentation && (a(this, "documentation", t2.documentation), a(this, "documentationUrl", t2.documentationUrl)), u(this, "idempotentMembers", function() {
        var e3 = [], t3 = n2.input, r3 = t3.members;
        if (!t3.members)
          return e3;
        for (var i2 in r3)
          r3.hasOwnProperty(i2) && true === r3[i2].isIdempotent && e3.push(i2);
        return e3;
      }), u(this, "hasEventOutput", function() {
        return i(n2.output);
      });
    }
    function i(e2) {
      var t2 = e2.members, r2 = e2.payload;
      if (!e2.members)
        return false;
      if (r2)
        return t2[r2].isEventStream;
      for (var n2 in t2)
        if (!t2.hasOwnProperty(n2) && true === t2[n2].isEventStream)
          return true;
      return false;
    }
    var o = e("./shape"), s = e("../util"), a = s.property, u = s.memoizedProperty;
    t.exports = n;
  }, {"../util": 118, "./shape": 70}], 61: [function(e, t, r) {
    var n = e("./core"), i = n.util.inherit;
    n.Endpoint = i({constructor: function(e2, t2) {
      if (n.util.hideProperties(this, ["slashes", "auth", "hash", "search", "query"]), void 0 === e2 || null === e2)
        throw new Error("Invalid endpoint: " + e2);
      if ("string" != typeof e2)
        return n.util.copy(e2);
      e2.match(/^http/) || (e2 = ((t2 && void 0 !== t2.sslEnabled ? t2.sslEnabled : n.config.sslEnabled) ? "https" : "http") + "://" + e2), n.util.update(this, n.util.urlParse(e2)), this.port ? this.port = parseInt(this.port, 10) : this.port = "https:" === this.protocol ? 443 : 80;
    }}), n.HttpRequest = i({constructor: function(e2, t2) {
      e2 = new n.Endpoint(e2), this.method = "POST", this.path = e2.path || "/", this.headers = {}, this.body = "", this.endpoint = e2, this.region = t2, this._userAgent = "", this.setUserAgent();
    }, setUserAgent: function() {
      this._userAgent = this.headers[this.getUserAgentHeaderName()] = n.util.userAgent();
    }, getUserAgentHeaderName: function() {
      return (n.util.isBrowser() ? "X-Amz-" : "") + "User-Agent";
    }, appendToUserAgent: function(e2) {
      "string" == typeof e2 && e2 && (this._userAgent += " " + e2), this.headers[this.getUserAgentHeaderName()] = this._userAgent;
    }, getUserAgent: function() {
      return this._userAgent;
    }, pathname: function() {
      return this.path.split("?", 1)[0];
    }, search: function() {
      var e2 = this.path.split("?", 2)[1];
      return e2 ? (e2 = n.util.queryStringParse(e2), n.util.queryParamsToString(e2)) : "";
    }, updateEndpoint: function(e2) {
      var t2 = new n.Endpoint(e2);
      this.endpoint = t2, this.path = t2.path || "/", this.headers.Host && (this.headers.Host = t2.host);
    }}), n.HttpResponse = i({constructor: function() {
      this.statusCode = void 0, this.headers = {}, this.body = void 0, this.streaming = false, this.stream = null;
    }, createUnbufferedStream: function() {
      return this.streaming = true, this.stream;
    }}), n.HttpClient = i({}), n.HttpClient.getInstance = function() {
      return void 0 === this.singleton && (this.singleton = new this()), this.singleton;
    };
  }, {"./core": 39}], 60: [function(e, t, r) {
    function n(e2) {
      if (!e2.service.api.operations)
        return "";
      var t2 = e2.service.api.operations[e2.operation];
      return t2 ? t2.authtype : "";
    }
    var i = e("./core"), o = e("./sequential_executor"), s = e("./discover_endpoint").discoverEndpoint;
    i.EventListeners = {Core: {}}, i.EventListeners = {Core: new o().addNamedListeners(function(e2, t2) {
      t2("VALIDATE_CREDENTIALS", "validate", function(e3, t3) {
        if (!e3.service.api.signatureVersion && !e3.service.config.signatureVersion)
          return t3();
        e3.service.config.getCredentials(function(r2) {
          r2 && (e3.response.error = i.util.error(r2, {code: "CredentialsError", message: "Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1"})), t3();
        });
      }), e2("VALIDATE_REGION", "validate", function(e3) {
        e3.service.config.region || e3.service.isGlobalEndpoint || (e3.response.error = i.util.error(new Error(), {code: "ConfigError", message: "Missing region in config"}));
      }), e2("BUILD_IDEMPOTENCY_TOKENS", "validate", function(e3) {
        if (e3.service.api.operations) {
          var t3 = e3.service.api.operations[e3.operation];
          if (t3) {
            var r2 = t3.idempotentMembers;
            if (r2.length) {
              for (var n2 = i.util.copy(e3.params), o2 = 0, s2 = r2.length; o2 < s2; o2++)
                n2[r2[o2]] || (n2[r2[o2]] = i.util.uuid.v4());
              e3.params = n2;
            }
          }
        }
      }), e2("VALIDATE_PARAMETERS", "validate", function(e3) {
        if (e3.service.api.operations) {
          var t3 = e3.service.api.operations[e3.operation].input, r2 = e3.service.config.paramValidation;
          new i.ParamValidator(r2).validate(t3, e3.params);
        }
      }), t2("COMPUTE_SHA256", "afterBuild", function(e3, t3) {
        if (e3.haltHandlersOnError(), e3.service.api.operations) {
          var r2 = e3.service.api.operations[e3.operation], n2 = r2 ? r2.authtype : "";
          if (!e3.service.api.signatureVersion && !n2 && !e3.service.config.signatureVersion)
            return t3();
          if (e3.service.getSignerClass(e3) === i.Signers.V4) {
            var o2 = e3.httpRequest.body || "";
            if (n2.indexOf("unsigned-body") >= 0)
              return e3.httpRequest.headers["X-Amz-Content-Sha256"] = "UNSIGNED-PAYLOAD", t3();
            i.util.computeSha256(o2, function(r3, n3) {
              r3 ? t3(r3) : (e3.httpRequest.headers["X-Amz-Content-Sha256"] = n3, t3());
            });
          } else
            t3();
        }
      }), e2("SET_CONTENT_LENGTH", "afterBuild", function(e3) {
        var t3 = n(e3), r2 = i.util.getRequestPayloadShape(e3);
        if (void 0 === e3.httpRequest.headers["Content-Length"])
          try {
            var o2 = i.util.string.byteLength(e3.httpRequest.body);
            e3.httpRequest.headers["Content-Length"] = o2;
          } catch (n2) {
            if (r2 && r2.isStreaming) {
              if (r2.requiresLength)
                throw n2;
              if (t3.indexOf("unsigned-body") >= 0)
                return void (e3.httpRequest.headers["Transfer-Encoding"] = "chunked");
              throw n2;
            }
            throw n2;
          }
      }), e2("SET_HTTP_HOST", "afterBuild", function(e3) {
        e3.httpRequest.headers.Host = e3.httpRequest.endpoint.host;
      }), e2("RESTART", "restart", function() {
        var e3 = this.response.error;
        e3 && e3.retryable && (this.httpRequest = new i.HttpRequest(this.service.endpoint, this.service.region), this.response.retryCount < this.service.config.maxRetries ? this.response.retryCount++ : this.response.error = null);
      }), t2("DISCOVER_ENDPOINT", "sign", s, true), t2("SIGN", "sign", function(e3, t3) {
        var r2 = e3.service, n2 = e3.service.api.operations || {}, i2 = n2[e3.operation], o2 = i2 ? i2.authtype : "";
        if (!r2.api.signatureVersion && !o2 && !r2.config.signatureVersion)
          return t3();
        r2.config.getCredentials(function(n3, o3) {
          if (n3)
            return e3.response.error = n3, t3();
          try {
            var s2 = r2.getSkewCorrectedDate(), a = r2.getSignerClass(e3), u = new a(e3.httpRequest, r2.api.signingName || r2.api.endpointPrefix, {signatureCache: r2.config.signatureCache, operation: i2, signatureVersion: r2.api.signatureVersion});
            u.setServiceClientId(r2._clientId), delete e3.httpRequest.headers.Authorization, delete e3.httpRequest.headers.Date, delete e3.httpRequest.headers["X-Amz-Date"], u.addAuthorization(o3, s2), e3.signedAt = s2;
          } catch (t4) {
            e3.response.error = t4;
          }
          t3();
        });
      }), e2("VALIDATE_RESPONSE", "validateResponse", function(e3) {
        this.service.successfulResponse(e3, this) ? (e3.data = {}, e3.error = null) : (e3.data = null, e3.error = i.util.error(new Error(), {code: "UnknownError", message: "An unknown error occurred."}));
      }), t2("SEND", "send", function(e3, t3) {
        function r2(r3) {
          e3.httpResponse.stream = r3;
          var n3 = e3.request.httpRequest.stream, o3 = e3.request.service, s3 = o3.api, a = e3.request.operation, u = s3.operations[a] || {};
          r3.on("headers", function(n4, s4, a2) {
            if (e3.request.emit("httpHeaders", [n4, s4, e3, a2]), !e3.httpResponse.streaming)
              if (2 === i.HttpClient.streamsApiVersion) {
                if (u.hasEventOutput && o3.successfulResponse(e3))
                  return e3.request.emit("httpDone"), void t3();
                r3.on("readable", function() {
                  var t4 = r3.read();
                  null !== t4 && e3.request.emit("httpData", [t4, e3]);
                });
              } else
                r3.on("data", function(t4) {
                  e3.request.emit("httpData", [t4, e3]);
                });
          }), r3.on("end", function() {
            if (!n3 || !n3.didCallback) {
              if (2 === i.HttpClient.streamsApiVersion && u.hasEventOutput && o3.successfulResponse(e3))
                return;
              e3.request.emit("httpDone"), t3();
            }
          });
        }
        function n2(t4) {
          t4.on("sendProgress", function(t5) {
            e3.request.emit("httpUploadProgress", [t5, e3]);
          }), t4.on("receiveProgress", function(t5) {
            e3.request.emit("httpDownloadProgress", [t5, e3]);
          });
        }
        function o2(r3) {
          if ("RequestAbortedError" !== r3.code) {
            var n3 = "TimeoutError" === r3.code ? r3.code : "NetworkingError";
            r3 = i.util.error(r3, {code: n3, region: e3.request.httpRequest.region, hostname: e3.request.httpRequest.endpoint.hostname, retryable: true});
          }
          e3.error = r3, e3.request.emit("httpError", [e3.error, e3], function() {
            t3();
          });
        }
        function s2() {
          var t4 = i.HttpClient.getInstance(), s3 = e3.request.service.config.httpOptions || {};
          try {
            n2(t4.handleRequest(e3.request.httpRequest, s3, r2, o2));
          } catch (e4) {
            o2(e4);
          }
        }
        e3.httpResponse._abortCallback = t3, e3.error = null, e3.data = null, (e3.request.service.getSkewCorrectedDate() - this.signedAt) / 1e3 >= 600 ? this.emit("sign", [this], function(e4) {
          e4 ? t3(e4) : s2();
        }) : s2();
      }), e2("HTTP_HEADERS", "httpHeaders", function(e3, t3, r2, n2) {
        r2.httpResponse.statusCode = e3, r2.httpResponse.statusMessage = n2, r2.httpResponse.headers = t3, r2.httpResponse.body = i.util.buffer.toBuffer(""), r2.httpResponse.buffers = [], r2.httpResponse.numBytes = 0;
        var o2 = t3.date || t3.Date, s2 = r2.request.service;
        if (o2) {
          var a = Date.parse(o2);
          s2.config.correctClockSkew && s2.isClockSkewed(a) && s2.applyClockOffset(a);
        }
      }), e2("HTTP_DATA", "httpData", function(e3, t3) {
        if (e3) {
          if (i.util.isNode()) {
            t3.httpResponse.numBytes += e3.length;
            var r2 = t3.httpResponse.headers["content-length"], n2 = {loaded: t3.httpResponse.numBytes, total: r2};
            t3.request.emit("httpDownloadProgress", [n2, t3]);
          }
          t3.httpResponse.buffers.push(i.util.buffer.toBuffer(e3));
        }
      }), e2("HTTP_DONE", "httpDone", function(e3) {
        if (e3.httpResponse.buffers && e3.httpResponse.buffers.length > 0) {
          var t3 = i.util.buffer.concat(e3.httpResponse.buffers);
          e3.httpResponse.body = t3;
        }
        delete e3.httpResponse.numBytes, delete e3.httpResponse.buffers;
      }), e2("FINALIZE_ERROR", "retry", function(e3) {
        e3.httpResponse.statusCode && (e3.error.statusCode = e3.httpResponse.statusCode, void 0 === e3.error.retryable && (e3.error.retryable = this.service.retryableError(e3.error, this)));
      }), e2("INVALIDATE_CREDENTIALS", "retry", function(e3) {
        if (e3.error)
          switch (e3.error.code) {
            case "RequestExpired":
            case "ExpiredTokenException":
            case "ExpiredToken":
              e3.error.retryable = true, e3.request.service.config.credentials.expired = true;
          }
      }), e2("EXPIRED_SIGNATURE", "retry", function(e3) {
        var t3 = e3.error;
        t3 && "string" == typeof t3.code && "string" == typeof t3.message && t3.code.match(/Signature/) && t3.message.match(/expired/) && (e3.error.retryable = true);
      }), e2("CLOCK_SKEWED", "retry", function(e3) {
        e3.error && this.service.clockSkewError(e3.error) && this.service.config.correctClockSkew && (e3.error.retryable = true);
      }), e2("REDIRECT", "retry", function(e3) {
        e3.error && e3.error.statusCode >= 300 && e3.error.statusCode < 400 && e3.httpResponse.headers.location && (this.httpRequest.endpoint = new i.Endpoint(e3.httpResponse.headers.location), this.httpRequest.headers.Host = this.httpRequest.endpoint.host, e3.error.redirect = true, e3.error.retryable = true);
      }), e2("RETRY_CHECK", "retry", function(e3) {
        e3.error && (e3.error.redirect && e3.redirectCount < e3.maxRedirects ? e3.error.retryDelay = 0 : e3.retryCount < e3.maxRetries && (e3.error.retryDelay = this.service.retryDelays(e3.retryCount, e3.error) || 0));
      }), t2("RESET_RETRY_STATE", "afterRetry", function(e3, t3) {
        var r2, n2 = false;
        e3.error && (r2 = e3.error.retryDelay || 0, e3.error.retryable && e3.retryCount < e3.maxRetries ? (e3.retryCount++, n2 = true) : e3.error.redirect && e3.redirectCount < e3.maxRedirects && (e3.redirectCount++, n2 = true)), n2 && r2 >= 0 ? (e3.error = null, setTimeout(t3, r2)) : t3();
      });
    }), CorePost: new o().addNamedListeners(function(e2) {
      e2("EXTRACT_REQUEST_ID", "extractData", i.util.extractRequestId), e2("EXTRACT_REQUEST_ID", "extractError", i.util.extractRequestId), e2("ENOTFOUND_ERROR", "httpError", function(e3) {
        if ("NetworkingError" === e3.code && "ENOTFOUND" === e3.errno) {
          var t2 = "Inaccessible host: `" + e3.hostname + "'. This service may not be available in the `" + e3.region + "' region.";
          this.response.error = i.util.error(new Error(t2), {code: "UnknownEndpoint", region: e3.region, hostname: e3.hostname, retryable: true, originalError: e3});
        }
      });
    }), Logger: new o().addNamedListeners(function(t2) {
      t2("LOG_REQUEST", "complete", function(t3) {
        function r2(e2, t4) {
          if (!t4)
            return t4;
          switch (e2.type) {
            case "structure":
              var n3 = {};
              return i.util.each(t4, function(t5, i2) {
                Object.prototype.hasOwnProperty.call(e2.members, t5) ? n3[t5] = r2(e2.members[t5], i2) : n3[t5] = i2;
              }), n3;
            case "list":
              var o3 = [];
              return i.util.arrayEach(t4, function(t5, n4) {
                o3.push(r2(e2.member, t5));
              }), o3;
            case "map":
              var s3 = {};
              return i.util.each(t4, function(t5, n4) {
                s3[t5] = r2(e2.value, n4);
              }), s3;
            default:
              return e2.isSensitive ? "***SensitiveInformation***" : t4;
          }
        }
        var n2 = t3.request, o2 = n2.service.config.logger;
        if (o2) {
          var s2 = function() {
            var s3 = t3.request.service.getSkewCorrectedDate().getTime(), a = (s3 - n2.startTime.getTime()) / 1e3, u = !!o2.isTTY, c = t3.httpResponse.statusCode, l = n2.params;
            n2.service.api.operations && n2.service.api.operations[n2.operation] && n2.service.api.operations[n2.operation].input && (l = r2(n2.service.api.operations[n2.operation].input, n2.params));
            var h = e("util").inspect(l, true, null), p = "";
            return u && (p += "[33m"), p += "[AWS " + n2.service.serviceIdentifier + " " + c, p += " " + a.toString() + "s " + t3.retryCount + " retries]", u && (p += "[0;1m"), p += " " + i.util.string.lowerFirst(n2.operation), p += "(" + h + ")", u && (p += "[0m"), p;
          }();
          "function" == typeof o2.log ? o2.log(s2) : "function" == typeof o2.write && o2.write(s2 + "\n");
        }
      });
    }), Json: new o().addNamedListeners(function(t2) {
      var r2 = e("./protocol/json");
      t2("BUILD", "build", r2.buildRequest), t2("EXTRACT_DATA", "extractData", r2.extractData), t2("EXTRACT_ERROR", "extractError", r2.extractError);
    }), Rest: new o().addNamedListeners(function(t2) {
      var r2 = e("./protocol/rest");
      t2("BUILD", "build", r2.buildRequest), t2("EXTRACT_DATA", "extractData", r2.extractData), t2("EXTRACT_ERROR", "extractError", r2.extractError);
    }), RestJson: new o().addNamedListeners(function(t2) {
      var r2 = e("./protocol/rest_json");
      t2("BUILD", "build", r2.buildRequest), t2("EXTRACT_DATA", "extractData", r2.extractData), t2("EXTRACT_ERROR", "extractError", r2.extractError);
    }), RestXml: new o().addNamedListeners(function(t2) {
      var r2 = e("./protocol/rest_xml");
      t2("BUILD", "build", r2.buildRequest), t2("EXTRACT_DATA", "extractData", r2.extractData), t2("EXTRACT_ERROR", "extractError", r2.extractError);
    }), Query: new o().addNamedListeners(function(t2) {
      var r2 = e("./protocol/query");
      t2("BUILD", "build", r2.buildRequest), t2("EXTRACT_DATA", "extractData", r2.extractData), t2("EXTRACT_ERROR", "extractError", r2.extractError);
    })};
  }, {"./core": 39, "./discover_endpoint": 47, "./protocol/json": 74, "./protocol/query": 75, "./protocol/rest": 76, "./protocol/rest_json": 77, "./protocol/rest_xml": 78, "./sequential_executor": 88, util: 20}], 88: [function(e, t, r) {
    var n = e("./core");
    n.SequentialExecutor = n.util.inherit({constructor: function() {
      this._events = {};
    }, listeners: function(e2) {
      return this._events[e2] ? this._events[e2].slice(0) : [];
    }, on: function(e2, t2, r2) {
      return this._events[e2] ? r2 ? this._events[e2].unshift(t2) : this._events[e2].push(t2) : this._events[e2] = [t2], this;
    }, onAsync: function(e2, t2, r2) {
      return t2._isAsync = true, this.on(e2, t2, r2);
    }, removeListener: function(e2, t2) {
      var r2 = this._events[e2];
      if (r2) {
        for (var n2 = r2.length, i = -1, o = 0; o < n2; ++o)
          r2[o] === t2 && (i = o);
        i > -1 && r2.splice(i, 1);
      }
      return this;
    }, removeAllListeners: function(e2) {
      return e2 ? delete this._events[e2] : this._events = {}, this;
    }, emit: function(e2, t2, r2) {
      r2 || (r2 = function() {
      });
      var n2 = this.listeners(e2), i = n2.length;
      return this.callListeners(n2, t2, r2), i > 0;
    }, callListeners: function(e2, t2, r2, i) {
      function o(i2) {
        if (i2 && (a = n.util.error(a || new Error(), i2), s._haltHandlersOnError))
          return r2.call(s, a);
        s.callListeners(e2, t2, r2, a);
      }
      for (var s = this, a = i || null; e2.length > 0; ) {
        var u = e2.shift();
        if (u._isAsync)
          return void u.apply(s, t2.concat([o]));
        try {
          u.apply(s, t2);
        } catch (e3) {
          a = n.util.error(a || new Error(), e3);
        }
        if (a && s._haltHandlersOnError)
          return void r2.call(s, a);
      }
      r2.call(s, a);
    }, addListeners: function(e2) {
      var t2 = this;
      return e2._events && (e2 = e2._events), n.util.each(e2, function(e3, r2) {
        "function" == typeof r2 && (r2 = [r2]), n.util.arrayEach(r2, function(r3) {
          t2.on(e3, r3);
        });
      }), t2;
    }, addNamedListener: function(e2, t2, r2, n2) {
      return this[e2] = r2, this.addListener(t2, r2, n2), this;
    }, addNamedAsyncListener: function(e2, t2, r2, n2) {
      return r2._isAsync = true, this.addNamedListener(e2, t2, r2, n2);
    }, addNamedListeners: function(e2) {
      var t2 = this;
      return e2(function() {
        t2.addNamedListener.apply(t2, arguments);
      }, function() {
        t2.addNamedAsyncListener.apply(t2, arguments);
      }), this;
    }}), n.SequentialExecutor.prototype.addListener = n.SequentialExecutor.prototype.on, t.exports = n.SequentialExecutor;
  }, {"./core": 39}], 78: [function(e, t, r) {
    function n(e2) {
      var t2 = e2.service.api.operations[e2.operation].input, r2 = new a.XML.Builder(), n2 = e2.params, i2 = t2.payload;
      if (i2) {
        var o2 = t2.members[i2];
        if (void 0 === (n2 = n2[i2]))
          return;
        if ("structure" === o2.type) {
          var s2 = o2.name;
          e2.httpRequest.body = r2.toXML(n2, o2, s2, true);
        } else
          e2.httpRequest.body = n2;
      } else
        e2.httpRequest.body = r2.toXML(n2, t2, t2.name || t2.shape || u.string.upperFirst(e2.operation) + "Request");
    }
    function i(e2) {
      c.buildRequest(e2), ["GET", "HEAD"].indexOf(e2.httpRequest.method) < 0 && n(e2);
    }
    function o(e2) {
      c.extractError(e2);
      var t2;
      try {
        t2 = new a.XML.Parser().parse(e2.httpResponse.body.toString());
      } catch (r2) {
        t2 = {Code: e2.httpResponse.statusCode, Message: e2.httpResponse.statusMessage};
      }
      t2.Errors && (t2 = t2.Errors), t2.Error && (t2 = t2.Error), t2.Code ? e2.error = u.error(new Error(), {code: t2.Code, message: t2.Message}) : e2.error = u.error(new Error(), {code: e2.httpResponse.statusCode, message: null});
    }
    function s(e2) {
      c.extractData(e2);
      var t2, r2 = e2.request, n2 = e2.httpResponse.body, i2 = r2.service.api.operations[r2.operation], o2 = i2.output, s2 = (i2.hasEventOutput, o2.payload);
      if (s2) {
        var l = o2.members[s2];
        l.isEventStream ? (t2 = new a.XML.Parser(), e2.data[s2] = u.createEventStream(2 === a.HttpClient.streamsApiVersion ? e2.httpResponse.stream : e2.httpResponse.body, t2, l)) : "structure" === l.type ? (t2 = new a.XML.Parser(), e2.data[s2] = t2.parse(n2.toString(), l)) : "binary" === l.type || l.isStreaming ? e2.data[s2] = n2 : e2.data[s2] = l.toType(n2);
      } else if (n2.length > 0) {
        t2 = new a.XML.Parser();
        var h = t2.parse(n2.toString(), o2);
        u.update(e2.data, h);
      }
    }
    var a = e("../core"), u = e("../util"), c = e("./rest");
    t.exports = {buildRequest: i, extractError: o, extractData: s};
  }, {"../core": 39, "../util": 118, "./rest": 76}], 77: [function(e, t, r) {
    function n(e2) {
      var t2 = new h(), r2 = e2.service.api.operations[e2.operation].input;
      if (r2.payload) {
        var n2 = {}, o2 = r2.members[r2.payload];
        if (void 0 === (n2 = e2.params[r2.payload]))
          return;
        "structure" === o2.type ? (e2.httpRequest.body = t2.build(n2, o2), i(e2)) : (e2.httpRequest.body = n2, ("binary" === o2.type || o2.isStreaming) && i(e2, true));
      } else {
        var s2 = t2.build(e2.params, r2);
        "{}" === s2 && "GET" === e2.httpRequest.method || (e2.httpRequest.body = s2), i(e2);
      }
    }
    function i(e2, t2) {
      var r2 = e2.service.api.operations[e2.operation];
      r2.input;
      if (!e2.httpRequest.headers["Content-Type"]) {
        var n2 = t2 ? "binary/octet-stream" : "application/json";
        e2.httpRequest.headers["Content-Type"] = n2;
      }
    }
    function o(e2) {
      c.buildRequest(e2), ["HEAD", "DELETE"].indexOf(e2.httpRequest.method) < 0 && n(e2);
    }
    function s(e2) {
      l.extractError(e2);
    }
    function a(e2) {
      c.extractData(e2);
      var t2, r2 = e2.request, n2 = r2.service.api.operations[r2.operation], i2 = r2.service.api.operations[r2.operation].output || {};
      n2.hasEventOutput;
      if (i2.payload) {
        var o2 = i2.members[i2.payload], s2 = e2.httpResponse.body;
        if (o2.isEventStream)
          t2 = new p(), e2.data[payload] = u.createEventStream(2 === AWS.HttpClient.streamsApiVersion ? e2.httpResponse.stream : s2, t2, o2);
        else if ("structure" === o2.type || "list" === o2.type) {
          var t2 = new p();
          e2.data[i2.payload] = t2.parse(s2, o2);
        } else
          "binary" === o2.type || o2.isStreaming ? e2.data[i2.payload] = s2 : e2.data[i2.payload] = o2.toType(s2);
      } else {
        var a2 = e2.data;
        l.extractData(e2), e2.data = u.merge(a2, e2.data);
      }
    }
    var u = e("../util"), c = e("./rest"), l = e("./json"), h = e("../json/builder"), p = e("../json/parser");
    t.exports = {buildRequest: o, extractError: s, extractData: a};
  }, {"../json/builder": 63, "../json/parser": 64, "../util": 118, "./json": 74, "./rest": 76}], 76: [function(e, t, r) {
    function n(e2) {
      e2.httpRequest.method = e2.service.api.operations[e2.operation].httpMethod;
    }
    function i(e2, t2, r2, n2) {
      var i2 = [e2, t2].join("/");
      i2 = i2.replace(/\/+/g, "/");
      var o2 = {}, s2 = false;
      if (l.each(r2.members, function(e3, t3) {
        var r3 = n2[e3];
        if (null !== r3 && void 0 !== r3)
          if ("uri" === t3.location) {
            var a3 = new RegExp("\\{" + t3.name + "(\\+)?\\}");
            i2 = i2.replace(a3, function(e4, t4) {
              return (t4 ? l.uriEscapePath : l.uriEscape)(String(r3));
            });
          } else
            "querystring" === t3.location && (s2 = true, "list" === t3.type ? o2[t3.name] = r3.map(function(e4) {
              return l.uriEscape(t3.member.toWireFormat(e4).toString());
            }) : "map" === t3.type ? l.each(r3, function(e4, t4) {
              Array.isArray(t4) ? o2[e4] = t4.map(function(e5) {
                return l.uriEscape(String(e5));
              }) : o2[e4] = l.uriEscape(String(t4));
            }) : o2[t3.name] = l.uriEscape(t3.toWireFormat(r3).toString()));
      }), s2) {
        i2 += i2.indexOf("?") >= 0 ? "&" : "?";
        var a2 = [];
        l.arrayEach(Object.keys(o2).sort(), function(e3) {
          Array.isArray(o2[e3]) || (o2[e3] = [o2[e3]]);
          for (var t3 = 0; t3 < o2[e3].length; t3++)
            a2.push(l.uriEscape(String(e3)) + "=" + o2[e3][t3]);
        }), i2 += a2.join("&");
      }
      return i2;
    }
    function o(e2) {
      var t2 = e2.service.api.operations[e2.operation], r2 = t2.input, n2 = i(e2.httpRequest.endpoint.path, t2.httpPath, r2, e2.params);
      e2.httpRequest.path = n2;
    }
    function s(e2) {
      var t2 = e2.service.api.operations[e2.operation];
      l.each(t2.input.members, function(t3, r2) {
        var n2 = e2.params[t3];
        null !== n2 && void 0 !== n2 && ("headers" === r2.location && "map" === r2.type ? l.each(n2, function(t4, n3) {
          e2.httpRequest.headers[r2.name + t4] = n3;
        }) : "header" === r2.location && (n2 = r2.toWireFormat(n2).toString(), r2.isJsonValue && (n2 = l.base64.encode(n2)), e2.httpRequest.headers[r2.name] = n2));
      });
    }
    function a(e2) {
      n(e2), o(e2), s(e2), h(e2);
    }
    function u() {
    }
    function c(e2) {
      var t2 = e2.request, r2 = {}, n2 = e2.httpResponse, i2 = t2.service.api.operations[t2.operation], o2 = i2.output, s2 = {};
      l.each(n2.headers, function(e3, t3) {
        s2[e3.toLowerCase()] = t3;
      }), l.each(o2.members, function(e3, t3) {
        var i3 = (t3.name || e3).toLowerCase();
        if ("headers" === t3.location && "map" === t3.type) {
          r2[e3] = {};
          var o3 = t3.isLocationName ? t3.name : "", a2 = new RegExp("^" + o3 + "(.+)", "i");
          l.each(n2.headers, function(t4, n3) {
            var i4 = t4.match(a2);
            null !== i4 && (r2[e3][i4[1]] = n3);
          });
        } else if ("header" === t3.location) {
          if (void 0 !== s2[i3]) {
            var u2 = t3.isJsonValue ? l.base64.decode(s2[i3]) : s2[i3];
            r2[e3] = t3.toType(u2);
          }
        } else
          "statusCode" === t3.location && (r2[e3] = parseInt(n2.statusCode, 10));
      }), e2.data = r2;
    }
    var l = e("../util"), h = e("./helpers").populateHostPrefix;
    t.exports = {buildRequest: a, extractError: u, extractData: c, generateURI: i};
  }, {"../util": 118, "./helpers": 73}], 75: [function(e, t, r) {
    function n(e2) {
      var t2 = e2.service.api.operations[e2.operation], r2 = e2.httpRequest;
      r2.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8", r2.params = {Version: e2.service.api.apiVersion, Action: t2.name}, new u().serialize(e2.params, t2.input, function(e3, t3) {
        r2.params[e3] = t3;
      }), r2.body = a.queryParamsToString(r2.params), l(e2);
    }
    function i(e2) {
      var t2, r2 = e2.httpResponse.body.toString();
      if (r2.match("<UnknownOperationException"))
        t2 = {Code: "UnknownOperation", Message: "Unknown operation " + e2.request.operation};
      else
        try {
          t2 = new s.XML.Parser().parse(r2);
        } catch (r3) {
          t2 = {Code: e2.httpResponse.statusCode, Message: e2.httpResponse.statusMessage};
        }
      t2.requestId && !e2.requestId && (e2.requestId = t2.requestId), t2.Errors && (t2 = t2.Errors), t2.Error && (t2 = t2.Error), t2.Code ? e2.error = a.error(new Error(), {code: t2.Code, message: t2.Message}) : e2.error = a.error(new Error(), {code: e2.httpResponse.statusCode, message: null});
    }
    function o(e2) {
      var t2 = e2.request, r2 = t2.service.api.operations[t2.operation], n2 = r2.output || {}, i2 = n2;
      if (i2.resultWrapper) {
        var o2 = c.create({type: "structure"});
        o2.members[i2.resultWrapper] = n2, o2.memberNames = [i2.resultWrapper], a.property(n2, "name", n2.resultWrapper), n2 = o2;
      }
      var u2 = new s.XML.Parser();
      if (n2 && n2.members && !n2.members._XAMZRequestId) {
        var l2 = c.create({type: "string"}, {api: {protocol: "query"}}, "requestId");
        n2.members._XAMZRequestId = l2;
      }
      var h = u2.parse(e2.httpResponse.body.toString(), n2);
      e2.requestId = h._XAMZRequestId || h.requestId, h._XAMZRequestId && delete h._XAMZRequestId, i2.resultWrapper && h[i2.resultWrapper] && (a.update(h, h[i2.resultWrapper]), delete h[i2.resultWrapper]), e2.data = h;
    }
    var s = e("../core"), a = e("../util"), u = e("../query/query_param_serializer"), c = e("../model/shape"), l = e("./helpers").populateHostPrefix;
    t.exports = {buildRequest: n, extractError: i, extractData: o};
  }, {"../core": 39, "../model/shape": 70, "../query/query_param_serializer": 79, "../util": 118, "./helpers": 73}], 79: [function(e, t, r) {
    function n() {
    }
    function i(e2) {
      return e2.isQueryName || "ec2" !== e2.api.protocol ? e2.name : e2.name[0].toUpperCase() + e2.name.substr(1);
    }
    function o(e2, t2, r2, n2) {
      c.each(r2.members, function(r3, o2) {
        var s2 = t2[r3];
        if (null !== s2 && void 0 !== s2) {
          var a2 = i(o2);
          a2 = e2 ? e2 + "." + a2 : a2, u(a2, s2, o2, n2);
        }
      });
    }
    function s(e2, t2, r2, n2) {
      var i2 = 1;
      c.each(t2, function(t3, o2) {
        var s2 = r2.flattened ? "." : ".entry.", a2 = s2 + i2++ + ".", c2 = a2 + (r2.key.name || "key"), l = a2 + (r2.value.name || "value");
        u(e2 + c2, t3, r2.key, n2), u(e2 + l, o2, r2.value, n2);
      });
    }
    function a(e2, t2, r2, n2) {
      var o2 = r2.member || {};
      if (0 === t2.length)
        return void n2.call(this, e2, null);
      c.arrayEach(t2, function(t3, s2) {
        var a2 = "." + (s2 + 1);
        if ("ec2" === r2.api.protocol)
          a2 += "";
        else if (r2.flattened) {
          if (o2.name) {
            var c2 = e2.split(".");
            c2.pop(), c2.push(i(o2)), e2 = c2.join(".");
          }
        } else
          a2 = "." + (o2.name ? o2.name : "member") + a2;
        u(e2 + a2, t3, o2, n2);
      });
    }
    function u(e2, t2, r2, n2) {
      null !== t2 && void 0 !== t2 && ("structure" === r2.type ? o(e2, t2, r2, n2) : "list" === r2.type ? a(e2, t2, r2, n2) : "map" === r2.type ? s(e2, t2, r2, n2) : n2(e2, r2.toWireFormat(t2).toString()));
    }
    var c = e("../util");
    n.prototype.serialize = function(e2, t2, r2) {
      o("", e2, t2, r2);
    }, t.exports = n;
  }, {"../util": 118}], 70: [function(e, t, r) {
    function n(e2, t2, r2) {
      null !== r2 && void 0 !== r2 && y.property.apply(this, arguments);
    }
    function i(e2, t2) {
      e2.constructor.prototype[t2] || y.memoizedProperty.apply(this, arguments);
    }
    function o(e2, t2, r2) {
      t2 = t2 || {}, n(this, "shape", e2.shape), n(this, "api", t2.api, false), n(this, "type", e2.type), n(this, "enum", e2.enum), n(this, "min", e2.min), n(this, "max", e2.max), n(this, "pattern", e2.pattern), n(this, "location", e2.location || this.location || "body"), n(this, "name", this.name || e2.xmlName || e2.queryName || e2.locationName || r2), n(this, "isStreaming", e2.streaming || this.isStreaming || false), n(this, "requiresLength", e2.requiresLength, false), n(this, "isComposite", e2.isComposite || false), n(this, "isShape", true, false), n(this, "isQueryName", Boolean(e2.queryName), false), n(this, "isLocationName", Boolean(e2.locationName), false), n(this, "isIdempotent", true === e2.idempotencyToken), n(this, "isJsonValue", true === e2.jsonvalue), n(this, "isSensitive", true === e2.sensitive || e2.prototype && true === e2.prototype.sensitive), n(this, "isEventStream", Boolean(e2.eventstream), false), n(this, "isEvent", Boolean(e2.event), false), n(this, "isEventPayload", Boolean(e2.eventpayload), false), n(this, "isEventHeader", Boolean(e2.eventheader), false), n(this, "isTimestampFormatSet", Boolean(e2.timestampFormat) || e2.prototype && true === e2.prototype.isTimestampFormatSet, false), n(this, "endpointDiscoveryId", Boolean(e2.endpointdiscoveryid), false), n(this, "hostLabel", Boolean(e2.hostLabel), false), t2.documentation && (n(this, "documentation", e2.documentation), n(this, "documentationUrl", e2.documentationUrl)), e2.xmlAttribute && n(this, "isXmlAttribute", e2.xmlAttribute || false), n(this, "defaultValue", null), this.toWireFormat = function(e3) {
        return null === e3 || void 0 === e3 ? "" : e3;
      }, this.toType = function(e3) {
        return e3;
      };
    }
    function s(e2) {
      o.apply(this, arguments), n(this, "isComposite", true), e2.flattened && n(this, "flattened", e2.flattened || false);
    }
    function a(e2, t2) {
      var r2 = this, a2 = null, u2 = !this.isShape;
      s.apply(this, arguments), u2 && (n(this, "defaultValue", function() {
        return {};
      }), n(this, "members", {}), n(this, "memberNames", []), n(this, "required", []), n(this, "isRequired", function() {
        return false;
      })), e2.members && (n(this, "members", new g(e2.members, t2, function(e3, r3) {
        return o.create(r3, t2, e3);
      })), i(this, "memberNames", function() {
        return e2.xmlOrder || Object.keys(e2.members);
      }), e2.event && (i(this, "eventPayloadMemberName", function() {
        for (var e3 = r2.members, t3 = r2.memberNames, n2 = 0, i2 = t3.length; n2 < i2; n2++)
          if (e3[t3[n2]].isEventPayload)
            return t3[n2];
      }), i(this, "eventHeaderMemberNames", function() {
        for (var e3 = r2.members, t3 = r2.memberNames, n2 = [], i2 = 0, o2 = t3.length; i2 < o2; i2++)
          e3[t3[i2]].isEventHeader && n2.push(t3[i2]);
        return n2;
      }))), e2.required && (n(this, "required", e2.required), n(this, "isRequired", function(t3) {
        if (!a2) {
          a2 = {};
          for (var r3 = 0; r3 < e2.required.length; r3++)
            a2[e2.required[r3]] = true;
        }
        return a2[t3];
      }, false, true)), n(this, "resultWrapper", e2.resultWrapper || null), e2.payload && n(this, "payload", e2.payload), "string" == typeof e2.xmlNamespace ? n(this, "xmlNamespaceUri", e2.xmlNamespace) : "object" == typeof e2.xmlNamespace && (n(this, "xmlNamespacePrefix", e2.xmlNamespace.prefix), n(this, "xmlNamespaceUri", e2.xmlNamespace.uri));
    }
    function u(e2, t2) {
      var r2 = this, a2 = !this.isShape;
      if (s.apply(this, arguments), a2 && n(this, "defaultValue", function() {
        return [];
      }), e2.member && i(this, "member", function() {
        return o.create(e2.member, t2);
      }), this.flattened) {
        var u2 = this.name;
        i(this, "name", function() {
          return r2.member.name || u2;
        });
      }
    }
    function c(e2, t2) {
      var r2 = !this.isShape;
      s.apply(this, arguments), r2 && (n(this, "defaultValue", function() {
        return {};
      }), n(this, "key", o.create({type: "string"}, t2)), n(this, "value", o.create({type: "string"}, t2))), e2.key && i(this, "key", function() {
        return o.create(e2.key, t2);
      }), e2.value && i(this, "value", function() {
        return o.create(e2.value, t2);
      });
    }
    function l(e2) {
      var t2 = this;
      if (o.apply(this, arguments), e2.timestampFormat)
        n(this, "timestampFormat", e2.timestampFormat);
      else if (t2.isTimestampFormatSet && this.timestampFormat)
        n(this, "timestampFormat", this.timestampFormat);
      else if ("header" === this.location)
        n(this, "timestampFormat", "rfc822");
      else if ("querystring" === this.location)
        n(this, "timestampFormat", "iso8601");
      else if (this.api)
        switch (this.api.protocol) {
          case "json":
          case "rest-json":
            n(this, "timestampFormat", "unixTimestamp");
            break;
          case "rest-xml":
          case "query":
          case "ec2":
            n(this, "timestampFormat", "iso8601");
        }
      this.toType = function(e3) {
        return null === e3 || void 0 === e3 ? null : "function" == typeof e3.toUTCString ? e3 : "string" == typeof e3 || "number" == typeof e3 ? y.date.parseTimestamp(e3) : null;
      }, this.toWireFormat = function(e3) {
        return y.date.format(e3, t2.timestampFormat);
      };
    }
    function h() {
      o.apply(this, arguments);
      var e2 = ["rest-xml", "query", "ec2"];
      this.toType = function(t2) {
        return t2 = this.api && e2.indexOf(this.api.protocol) > -1 ? t2 || "" : t2, this.isJsonValue ? JSON.parse(t2) : t2 && "function" == typeof t2.toString ? t2.toString() : t2;
      }, this.toWireFormat = function(e3) {
        return this.isJsonValue ? JSON.stringify(e3) : e3;
      };
    }
    function p() {
      o.apply(this, arguments), this.toType = function(e2) {
        return null === e2 || void 0 === e2 ? null : parseFloat(e2);
      }, this.toWireFormat = this.toType;
    }
    function f() {
      o.apply(this, arguments), this.toType = function(e2) {
        return null === e2 || void 0 === e2 ? null : parseInt(e2, 10);
      }, this.toWireFormat = this.toType;
    }
    function d() {
      o.apply(this, arguments), this.toType = function(e2) {
        var t2 = y.base64.decode(e2);
        if (this.isSensitive && y.isNode() && "function" == typeof y.Buffer.alloc) {
          var r2 = y.Buffer.alloc(t2.length, t2);
          t2.fill(0), t2 = r2;
        }
        return t2;
      }, this.toWireFormat = y.base64.encode;
    }
    function m() {
      d.apply(this, arguments);
    }
    function v() {
      o.apply(this, arguments), this.toType = function(e2) {
        return "boolean" == typeof e2 ? e2 : null === e2 || void 0 === e2 ? null : "true" === e2;
      };
    }
    var g = e("./collection"), y = e("../util");
    o.normalizedTypes = {character: "string", double: "float", long: "integer", short: "integer", biginteger: "integer", bigdecimal: "float", blob: "binary"}, o.types = {structure: a, list: u, map: c, boolean: v, timestamp: l, float: p, integer: f, string: h, base64: m, binary: d}, o.resolve = function(e2, t2) {
      if (e2.shape) {
        var r2 = t2.api.shapes[e2.shape];
        if (!r2)
          throw new Error("Cannot find shape reference: " + e2.shape);
        return r2;
      }
      return null;
    }, o.create = function(e2, t2, r2) {
      if (e2.isShape)
        return e2;
      var n2 = o.resolve(e2, t2);
      if (n2) {
        var i2 = Object.keys(e2);
        t2.documentation || (i2 = i2.filter(function(e3) {
          return !e3.match(/documentation/);
        }));
        var s2 = function() {
          n2.constructor.call(this, e2, t2, r2);
        };
        return s2.prototype = n2, new s2();
      }
      e2.type || (e2.members ? e2.type = "structure" : e2.member ? e2.type = "list" : e2.key ? e2.type = "map" : e2.type = "string");
      var a2 = e2.type;
      if (o.normalizedTypes[e2.type] && (e2.type = o.normalizedTypes[e2.type]), o.types[e2.type])
        return new o.types[e2.type](e2, t2, r2);
      throw new Error("Unrecognized shape type: " + a2);
    }, o.shapes = {StructureShape: a, ListShape: u, MapShape: c, StringShape: h, BooleanShape: v, Base64Shape: m}, t.exports = o;
  }, {"../util": 118, "./collection": 66}], 66: [function(e, t, r) {
    function n(e2, t2, r2, n2) {
      o(this, n2(e2), function() {
        return r2(e2, t2);
      });
    }
    function i(e2, t2, r2, i2, o2) {
      i2 = i2 || String;
      var s = this;
      for (var a in e2)
        Object.prototype.hasOwnProperty.call(e2, a) && (n.call(s, a, e2[a], r2, i2), o2 && o2(a, e2[a]));
    }
    var o = e("../util").memoizedProperty;
    t.exports = i;
  }, {"../util": 118}], 74: [function(e, t, r) {
    function n(e2) {
      var t2 = e2.httpRequest, r2 = e2.service.api, n2 = r2.targetPrefix + "." + r2.operations[e2.operation].name, i2 = r2.jsonVersion || "1.0", o2 = r2.operations[e2.operation].input, s2 = new a();
      1 === i2 && (i2 = "1.0"), t2.body = s2.build(e2.params || {}, o2), t2.headers["Content-Type"] = "application/x-amz-json-" + i2, t2.headers["X-Amz-Target"] = n2, c(e2);
    }
    function i(e2) {
      var t2 = {}, r2 = e2.httpResponse;
      if (t2.code = r2.headers["x-amzn-errortype"] || "UnknownError", "string" == typeof t2.code && (t2.code = t2.code.split(":")[0]), r2.body.length > 0)
        try {
          var n2 = JSON.parse(r2.body.toString());
          (n2.__type || n2.code) && (t2.code = (n2.__type || n2.code).split("#").pop()), "RequestEntityTooLarge" === t2.code ? t2.message = "Request body must be less than 1 MB" : t2.message = n2.message || n2.Message || null;
        } catch (n3) {
          t2.statusCode = r2.statusCode, t2.message = r2.statusMessage;
        }
      else
        t2.statusCode = r2.statusCode, t2.message = r2.statusCode.toString();
      e2.error = s.error(new Error(), t2);
    }
    function o(e2) {
      var t2 = e2.httpResponse.body.toString() || "{}";
      if (false === e2.request.service.config.convertResponseTypes)
        e2.data = JSON.parse(t2);
      else {
        var r2 = e2.request.service.api.operations[e2.request.operation], n2 = r2.output || {}, i2 = new u();
        e2.data = i2.parse(t2, n2);
      }
    }
    var s = e("../util"), a = e("../json/builder"), u = e("../json/parser"), c = e("./helpers").populateHostPrefix;
    t.exports = {buildRequest: n, extractError: i, extractData: o};
  }, {"../json/builder": 63, "../json/parser": 64, "../util": 118, "./helpers": 73}], 73: [function(e, t, r) {
    function n(e2) {
      if (!e2.service.config.hostPrefixEnabled)
        return e2;
      var t2 = e2.service.api.operations[e2.operation];
      if (i(e2))
        return e2;
      if (t2.endpoint && t2.endpoint.hostPrefix) {
        var r2 = t2.endpoint.hostPrefix, n2 = o(r2, e2.params, t2.input);
        s(e2.httpRequest.endpoint, n2), a(e2.httpRequest.endpoint.hostname);
      }
      return e2;
    }
    function i(e2) {
      var t2 = e2.service.api, r2 = t2.operations[e2.operation], n2 = t2.endpointOperation && t2.endpointOperation === u.string.lowerFirst(r2.name);
      return "NULL" !== r2.endpointDiscoveryRequired || true === n2;
    }
    function o(e2, t2, r2) {
      return u.each(r2.members, function(r3, n2) {
        if (true === n2.hostLabel) {
          if ("string" != typeof t2[r3] || "" === t2[r3])
            throw u.error(new Error(), {message: "Parameter " + r3 + " should be a non-empty string.", code: "InvalidParameter"});
          var i2 = new RegExp("\\{" + r3 + "\\}", "g");
          e2 = e2.replace(i2, t2[r3]);
        }
      }), e2;
    }
    function s(e2, t2) {
      e2.host && (e2.host = t2 + e2.host), e2.hostname && (e2.hostname = t2 + e2.hostname);
    }
    function a(e2) {
      var t2 = e2.split("."), r2 = /^[a-zA-Z0-9]{1}$|^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$/;
      u.arrayEach(t2, function(e3) {
        if (!e3.length || e3.length < 1 || e3.length > 63)
          throw u.error(new Error(), {code: "ValidationError", message: "Hostname label length should be between 1 to 63 characters, inclusive."});
        if (!r2.test(e3))
          throw c.util.error(new Error(), {code: "ValidationError", message: e3 + " is not hostname compatible."});
      });
    }
    var u = e("../util"), c = e("../core");
    t.exports = {populateHostPrefix: n};
  }, {"../core": 39, "../util": 118}], 64: [function(e, t, r) {
    function n() {
    }
    function i(e2, t2) {
      if (t2 && void 0 !== e2)
        switch (t2.type) {
          case "structure":
            return o(e2, t2);
          case "map":
            return a(e2, t2);
          case "list":
            return s(e2, t2);
          default:
            return u(e2, t2);
        }
    }
    function o(e2, t2) {
      if (null != e2) {
        var r2 = {}, n2 = t2.members;
        return c.each(n2, function(t3, n3) {
          var o2 = n3.isLocationName ? n3.name : t3;
          if (Object.prototype.hasOwnProperty.call(e2, o2)) {
            var s2 = e2[o2], a2 = i(s2, n3);
            void 0 !== a2 && (r2[t3] = a2);
          }
        }), r2;
      }
    }
    function s(e2, t2) {
      if (null != e2) {
        var r2 = [];
        return c.arrayEach(e2, function(e3) {
          var n2 = i(e3, t2.member);
          void 0 === n2 ? r2.push(null) : r2.push(n2);
        }), r2;
      }
    }
    function a(e2, t2) {
      if (null != e2) {
        var r2 = {};
        return c.each(e2, function(e3, n2) {
          var o2 = i(n2, t2.value);
          r2[e3] = void 0 === o2 ? null : o2;
        }), r2;
      }
    }
    function u(e2, t2) {
      return t2.toType(e2);
    }
    var c = e("../util");
    n.prototype.parse = function(e2, t2) {
      return i(JSON.parse(e2), t2);
    }, t.exports = n;
  }, {"../util": 118}], 63: [function(e, t, r) {
    function n() {
    }
    function i(e2, t2) {
      if (t2 && void 0 !== e2 && null !== e2)
        switch (t2.type) {
          case "structure":
            return o(e2, t2);
          case "map":
            return a(e2, t2);
          case "list":
            return s(e2, t2);
          default:
            return u(e2, t2);
        }
    }
    function o(e2, t2) {
      var r2 = {};
      return c.each(e2, function(e3, n2) {
        var o2 = t2.members[e3];
        if (o2) {
          if ("body" !== o2.location)
            return;
          var s2 = o2.isLocationName ? o2.name : e3, a2 = i(n2, o2);
          void 0 !== a2 && (r2[s2] = a2);
        }
      }), r2;
    }
    function s(e2, t2) {
      var r2 = [];
      return c.arrayEach(e2, function(e3) {
        var n2 = i(e3, t2.member);
        void 0 !== n2 && r2.push(n2);
      }), r2;
    }
    function a(e2, t2) {
      var r2 = {};
      return c.each(e2, function(e3, n2) {
        var o2 = i(n2, t2.value);
        void 0 !== o2 && (r2[e3] = o2);
      }), r2;
    }
    function u(e2, t2) {
      return t2.toWireFormat(e2);
    }
    var c = e("../util");
    n.prototype.build = function(e2, t2) {
      return JSON.stringify(i(e2, t2));
    }, t.exports = n;
  }, {"../util": 118}], 47: [function(e, t, r) {
    (function(r2) {
      function n(e2) {
        var t2 = e2.service, r3 = t2.api || {}, n2 = {};
        return t2.config.region && (n2.region = t2.config.region), r3.serviceId && (n2.serviceId = r3.serviceId), t2.config.credentials.accessKeyId && (n2.accessKeyId = t2.config.credentials.accessKeyId), n2;
      }
      function i(e2, t2, r3) {
        r3 && void 0 !== t2 && null !== t2 && "structure" === r3.type && r3.required && r3.required.length > 0 && m.arrayEach(r3.required, function(n2) {
          var o2 = r3.members[n2];
          if (true === o2.endpointDiscoveryId) {
            var s2 = o2.isLocationName ? o2.name : n2;
            e2[s2] = String(t2[n2]);
          } else
            i(e2, t2[n2], o2);
        });
      }
      function o(e2, t2) {
        var r3 = {};
        return i(r3, e2.params, t2), r3;
      }
      function s(e2) {
        var t2 = e2.service, r3 = t2.api, i2 = r3.operations ? r3.operations[e2.operation] : void 0, s2 = i2 ? i2.input : void 0, a2 = o(e2, s2), c2 = n(e2);
        Object.keys(a2).length > 0 && (c2 = m.update(c2, a2), i2 && (c2.operation = i2.name));
        var l2 = d.endpointCache.get(c2);
        if (!l2 || 1 !== l2.length || "" !== l2[0].Address)
          if (l2 && l2.length > 0)
            e2.httpRequest.updateEndpoint(l2[0].Address);
          else {
            var h2 = t2.makeRequest(r3.endpointOperation, {Operation: i2.name, Identifiers: a2});
            u(h2), h2.removeListener("validate", d.EventListeners.Core.VALIDATE_PARAMETERS), h2.removeListener("retry", d.EventListeners.Core.RETRY_CHECK), d.endpointCache.put(c2, [{Address: "", CachePeriodInMinutes: 1}]), h2.send(function(e3, t3) {
              t3 && t3.Endpoints ? d.endpointCache.put(c2, t3.Endpoints) : e3 && d.endpointCache.put(c2, [{Address: "", CachePeriodInMinutes: 1}]);
            });
          }
      }
      function a(e2, t2) {
        var r3 = e2.service, i2 = r3.api, s2 = i2.operations ? i2.operations[e2.operation] : void 0, a2 = s2 ? s2.input : void 0, c2 = o(e2, a2), l2 = n(e2);
        Object.keys(c2).length > 0 && (l2 = m.update(l2, c2), s2 && (l2.operation = s2.name));
        var h2 = d.EndpointCache.getKeyString(l2), p2 = d.endpointCache.get(h2);
        if (p2 && 1 === p2.length && "" === p2[0].Address)
          return g[h2] || (g[h2] = []), void g[h2].push({request: e2, callback: t2});
        if (p2 && p2.length > 0)
          e2.httpRequest.updateEndpoint(p2[0].Address), t2();
        else {
          var f2 = r3.makeRequest(i2.endpointOperation, {Operation: s2.name, Identifiers: c2});
          f2.removeListener("validate", d.EventListeners.Core.VALIDATE_PARAMETERS), u(f2), d.endpointCache.put(h2, [{Address: "", CachePeriodInMinutes: 60}]), f2.send(function(r4, n2) {
            if (r4) {
              if (e2.response.error = m.error(r4, {retryable: false}), d.endpointCache.remove(l2), g[h2]) {
                var i3 = g[h2];
                m.arrayEach(i3, function(e3) {
                  e3.request.response.error = m.error(r4, {retryable: false}), e3.callback();
                }), delete g[h2];
              }
            } else if (n2 && (d.endpointCache.put(h2, n2.Endpoints), e2.httpRequest.updateEndpoint(n2.Endpoints[0].Address), g[h2])) {
              var i3 = g[h2];
              m.arrayEach(i3, function(e3) {
                e3.request.httpRequest.updateEndpoint(n2.Endpoints[0].Address), e3.callback();
              }), delete g[h2];
            }
            t2();
          });
        }
      }
      function u(e2) {
        var t2 = e2.service.api, r3 = t2.apiVersion;
        r3 && !e2.httpRequest.headers["x-amz-api-version"] && (e2.httpRequest.headers["x-amz-api-version"] = r3);
      }
      function c(e2) {
        var t2 = e2.error, r3 = e2.httpResponse;
        if (t2 && ("InvalidEndpointException" === t2.code || 421 === r3.statusCode)) {
          var i2 = e2.request, s2 = i2.service.api.operations || {}, a2 = s2[i2.operation] ? s2[i2.operation].input : void 0, u2 = o(i2, a2), c2 = n(i2);
          Object.keys(u2).length > 0 && (c2 = m.update(c2, u2), s2[i2.operation] && (c2.operation = s2[i2.operation].name)), d.endpointCache.remove(c2);
        }
      }
      function l(e2) {
        if (e2._originalConfig && e2._originalConfig.endpoint && true === e2._originalConfig.endpointDiscoveryEnabled)
          throw m.error(new Error(), {code: "ConfigurationException", message: "Custom endpoint is supplied; endpointDiscoveryEnabled must not be true."});
        var t2 = d.config[e2.serviceIdentifier] || {};
        return Boolean(d.config.endpoint || t2.endpoint || e2._originalConfig && e2._originalConfig.endpoint);
      }
      function h(e2) {
        return ["false", "0"].indexOf(e2) >= 0;
      }
      function p(e2) {
        var t2 = e2.service || {};
        if (void 0 !== t2.config.endpointDiscoveryEnabled)
          return t2.config.endpointDiscoveryEnabled;
        if (!m.isBrowser()) {
          for (var n2 = 0; n2 < v.length; n2++) {
            var i2 = v[n2];
            if (Object.prototype.hasOwnProperty.call(r2.env, i2)) {
              if ("" === r2.env[i2] || void 0 === r2.env[i2])
                throw m.error(new Error(), {code: "ConfigurationException", message: "environmental variable " + i2 + " cannot be set to nothing"});
              return !h(r2.env[i2]);
            }
          }
          var o2 = {};
          try {
            o2 = d.util.iniLoader ? d.util.iniLoader.loadFrom({isConfig: true, filename: r2.env[d.util.sharedConfigFileEnv]}) : {};
          } catch (e3) {
          }
          var s2 = o2[r2.env.AWS_PROFILE || d.util.defaultProfile] || {};
          if (Object.prototype.hasOwnProperty.call(s2, "endpoint_discovery_enabled")) {
            if (void 0 === s2.endpoint_discovery_enabled)
              throw m.error(new Error(), {code: "ConfigurationException", message: "config file entry 'endpoint_discovery_enabled' cannot be set to nothing"});
            return !h(s2.endpoint_discovery_enabled);
          }
        }
      }
      function f(e2, t2) {
        var r3 = e2.service || {};
        if (l(r3) || e2.isPresigned())
          return t2();
        var n2 = r3.api.operations || {}, i2 = n2[e2.operation], o2 = i2 ? i2.endpointDiscoveryRequired : "NULL", u2 = p(e2), h2 = r3.api.hasRequiredEndpointDiscovery;
        switch ((u2 || h2) && e2.httpRequest.appendToUserAgent("endpoint-discovery"), o2) {
          case "OPTIONAL":
            (u2 || h2) && (s(e2), e2.addNamedListener("INVALIDATE_CACHED_ENDPOINTS", "extractError", c)), t2();
            break;
          case "REQUIRED":
            if (false === u2) {
              e2.response.error = m.error(new Error(), {code: "ConfigurationException", message: "Endpoint Discovery is disabled but " + r3.api.className + "." + e2.operation + "() requires it. Please check your configurations."}), t2();
              break;
            }
            e2.addNamedListener("INVALIDATE_CACHED_ENDPOINTS", "extractError", c), a(e2, t2);
            break;
          case "NULL":
          default:
            t2();
        }
      }
      var d = e("./core"), m = e("./util"), v = ["AWS_ENABLE_ENDPOINT_DISCOVERY", "AWS_ENDPOINT_DISCOVERY_ENABLED"], g = {};
      t.exports = {discoverEndpoint: f, requiredDiscoverEndpoint: a, optionalDiscoverEndpoint: s, marshallCustomIdentifiers: o, getCacheKey: n, invalidateCachedEndpoint: c};
    }).call(this, e("_process"));
  }, {"./core": 39, "./util": 118, _process: 8}], 118: [function(e, t, r) {
    (function(r2, n) {
      var i, o = {environment: "nodejs", engine: function() {
        if (o.isBrowser() && "undefined" != typeof navigator)
          return navigator.userAgent;
        var e2 = r2.platform + "/" + r2.version;
        return r2.env.AWS_EXECUTION_ENV && (e2 += " exec-env/" + r2.env.AWS_EXECUTION_ENV), e2;
      }, userAgent: function() {
        var t2 = o.environment, r3 = "aws-sdk-" + t2 + "/" + e("./core").VERSION;
        return "nodejs" === t2 && (r3 += " " + o.engine()), r3;
      }, uriEscape: function(e2) {
        var t2 = encodeURIComponent(e2);
        return t2 = t2.replace(/[^A-Za-z0-9_.~\-%]+/g, escape), t2 = t2.replace(/[*]/g, function(e3) {
          return "%" + e3.charCodeAt(0).toString(16).toUpperCase();
        });
      }, uriEscapePath: function(e2) {
        var t2 = [];
        return o.arrayEach(e2.split("/"), function(e3) {
          t2.push(o.uriEscape(e3));
        }), t2.join("/");
      }, urlParse: function(e2) {
        return o.url.parse(e2);
      }, urlFormat: function(e2) {
        return o.url.format(e2);
      }, queryStringParse: function(e2) {
        return o.querystring.parse(e2);
      }, queryParamsToString: function(e2) {
        var t2 = [], r3 = o.uriEscape, n2 = Object.keys(e2).sort();
        return o.arrayEach(n2, function(n3) {
          var i2 = e2[n3], s = r3(n3), a = s + "=";
          if (Array.isArray(i2)) {
            var u = [];
            o.arrayEach(i2, function(e3) {
              u.push(r3(e3));
            }), a = s + "=" + u.sort().join("&" + s + "=");
          } else
            void 0 !== i2 && null !== i2 && (a = s + "=" + r3(i2));
          t2.push(a);
        }), t2.join("&");
      }, readFileSync: function(t2) {
        return o.isBrowser() ? null : e("fs").readFileSync(t2, "utf-8");
      }, base64: {encode: function(e2) {
        if ("number" == typeof e2)
          throw o.error(new Error("Cannot base64 encode number " + e2));
        return null === e2 || void 0 === e2 ? e2 : o.buffer.toBuffer(e2).toString("base64");
      }, decode: function(e2) {
        if ("number" == typeof e2)
          throw o.error(new Error("Cannot base64 decode number " + e2));
        return null === e2 || void 0 === e2 ? e2 : o.buffer.toBuffer(e2, "base64");
      }}, buffer: {toBuffer: function(e2, t2) {
        return "function" == typeof o.Buffer.from && o.Buffer.from !== Uint8Array.from ? o.Buffer.from(e2, t2) : new o.Buffer(e2, t2);
      }, alloc: function(e2, t2, r3) {
        if ("number" != typeof e2)
          throw new Error("size passed to alloc must be a number.");
        if ("function" == typeof o.Buffer.alloc)
          return o.Buffer.alloc(e2, t2, r3);
        var n2 = new o.Buffer(e2);
        return void 0 !== t2 && "function" == typeof n2.fill && n2.fill(t2, void 0, void 0, r3), n2;
      }, toStream: function(e2) {
        o.Buffer.isBuffer(e2) || (e2 = o.buffer.toBuffer(e2));
        var t2 = new o.stream.Readable(), r3 = 0;
        return t2._read = function(n2) {
          if (r3 >= e2.length)
            return t2.push(null);
          var i2 = r3 + n2;
          i2 > e2.length && (i2 = e2.length), t2.push(e2.slice(r3, i2)), r3 = i2;
        }, t2;
      }, concat: function(e2) {
        var t2, r3 = 0, n2 = 0, i2 = null;
        for (t2 = 0; t2 < e2.length; t2++)
          r3 += e2[t2].length;
        for (i2 = o.buffer.alloc(r3), t2 = 0; t2 < e2.length; t2++)
          e2[t2].copy(i2, n2), n2 += e2[t2].length;
        return i2;
      }}, string: {byteLength: function(t2) {
        if (null === t2 || void 0 === t2)
          return 0;
        if ("string" == typeof t2 && (t2 = o.buffer.toBuffer(t2)), "number" == typeof t2.byteLength)
          return t2.byteLength;
        if ("number" == typeof t2.length)
          return t2.length;
        if ("number" == typeof t2.size)
          return t2.size;
        if ("string" == typeof t2.path)
          return e("fs").lstatSync(t2.path).size;
        throw o.error(new Error("Cannot determine length of " + t2), {object: t2});
      }, upperFirst: function(e2) {
        return e2[0].toUpperCase() + e2.substr(1);
      }, lowerFirst: function(e2) {
        return e2[0].toLowerCase() + e2.substr(1);
      }}, ini: {parse: function(e2) {
        var t2, r3 = {};
        return o.arrayEach(e2.split(/\r?\n/), function(e3) {
          e3 = e3.split(/(^|\s)[;#]/)[0];
          var n2 = e3.match(/^\s*\[([^\[\]]+)\]\s*$/);
          if (n2)
            t2 = n2[1];
          else if (t2) {
            var i2 = e3.match(/^\s*(.+?)\s*=\s*(.+?)\s*$/);
            i2 && (r3[t2] = r3[t2] || {}, r3[t2][i2[1]] = i2[2]);
          }
        }), r3;
      }}, fn: {noop: function() {
      }, callback: function(e2) {
        if (e2)
          throw e2;
      }, makeAsync: function(e2, t2) {
        return t2 && t2 <= e2.length ? e2 : function() {
          var t3 = Array.prototype.slice.call(arguments, 0);
          t3.pop()(e2.apply(null, t3));
        };
      }}, date: {getDate: function() {
        return i || (i = e("./core")), i.config.systemClockOffset ? new Date(new Date().getTime() + i.config.systemClockOffset) : new Date();
      }, iso8601: function(e2) {
        return void 0 === e2 && (e2 = o.date.getDate()), e2.toISOString().replace(/\.\d{3}Z$/, "Z");
      }, rfc822: function(e2) {
        return void 0 === e2 && (e2 = o.date.getDate()), e2.toUTCString();
      }, unixTimestamp: function(e2) {
        return void 0 === e2 && (e2 = o.date.getDate()), e2.getTime() / 1e3;
      }, from: function(e2) {
        return "number" == typeof e2 ? new Date(1e3 * e2) : new Date(e2);
      }, format: function(e2, t2) {
        return t2 || (t2 = "iso8601"), o.date[t2](o.date.from(e2));
      }, parseTimestamp: function(e2) {
        if ("number" == typeof e2)
          return new Date(1e3 * e2);
        if (e2.match(/^\d+$/))
          return new Date(1e3 * e2);
        if (e2.match(/^\d{4}/))
          return new Date(e2);
        if (e2.match(/^\w{3},/))
          return new Date(e2);
        throw o.error(new Error("unhandled timestamp format: " + e2), {code: "TimestampParserError"});
      }}, crypto: {crc32Table: [0, 1996959894, 3993919788, 2567524794, 124634137, 1886057615, 3915621685, 2657392035, 249268274, 2044508324, 3772115230, 2547177864, 162941995, 2125561021, 3887607047, 2428444049, 498536548, 1789927666, 4089016648, 2227061214, 450548861, 1843258603, 4107580753, 2211677639, 325883990, 1684777152, 4251122042, 2321926636, 335633487, 1661365465, 4195302755, 2366115317, 997073096, 1281953886, 3579855332, 2724688242, 1006888145, 1258607687, 3524101629, 2768942443, 901097722, 1119000684, 3686517206, 2898065728, 853044451, 1172266101, 3705015759, 2882616665, 651767980, 1373503546, 3369554304, 3218104598, 565507253, 1454621731, 3485111705, 3099436303, 671266974, 1594198024, 3322730930, 2970347812, 795835527, 1483230225, 3244367275, 3060149565, 1994146192, 31158534, 2563907772, 4023717930, 1907459465, 112637215, 2680153253, 3904427059, 2013776290, 251722036, 2517215374, 3775830040, 2137656763, 141376813, 2439277719, 3865271297, 1802195444, 476864866, 2238001368, 4066508878, 1812370925, 453092731, 2181625025, 4111451223, 1706088902, 314042704, 2344532202, 4240017532, 1658658271, 366619977, 2362670323, 4224994405, 1303535960, 984961486, 2747007092, 3569037538, 1256170817, 1037604311, 2765210733, 3554079995, 1131014506, 879679996, 2909243462, 3663771856, 1141124467, 855842277, 2852801631, 3708648649, 1342533948, 654459306, 3188396048, 3373015174, 1466479909, 544179635, 3110523913, 3462522015, 1591671054, 702138776, 2966460450, 3352799412, 1504918807, 783551873, 3082640443, 3233442989, 3988292384, 2596254646, 62317068, 1957810842, 3939845945, 2647816111, 81470997, 1943803523, 3814918930, 2489596804, 225274430, 2053790376, 3826175755, 2466906013, 167816743, 2097651377, 4027552580, 2265490386, 503444072, 1762050814, 4150417245, 2154129355, 426522225, 1852507879, 4275313526, 2312317920, 282753626, 1742555852, 4189708143, 2394877945, 397917763, 1622183637, 3604390888, 2714866558, 953729732, 1340076626, 3518719985, 2797360999, 1068828381, 1219638859, 3624741850, 2936675148, 906185462, 1090812512, 3747672003, 2825379669, 829329135, 1181335161, 3412177804, 3160834842, 628085408, 1382605366, 3423369109, 3138078467, 570562233, 1426400815, 3317316542, 2998733608, 733239954, 1555261956, 3268935591, 3050360625, 752459403, 1541320221, 2607071920, 3965973030, 1969922972, 40735498, 2617837225, 3943577151, 1913087877, 83908371, 2512341634, 3803740692, 2075208622, 213261112, 2463272603, 3855990285, 2094854071, 198958881, 2262029012, 4057260610, 1759359992, 534414190, 2176718541, 4139329115, 1873836001, 414664567, 2282248934, 4279200368, 1711684554, 285281116, 2405801727, 4167216745, 1634467795, 376229701, 2685067896, 3608007406, 1308918612, 956543938, 2808555105, 3495958263, 1231636301, 1047427035, 2932959818, 3654703836, 1088359270, 936918e3, 2847714899, 3736837829, 1202900863, 817233897, 3183342108, 3401237130, 1404277552, 615818150, 3134207493, 3453421203, 1423857449, 601450431, 3009837614, 3294710456, 1567103746, 711928724, 3020668471, 3272380065, 1510334235, 755167117], crc32: function(e2) {
        var t2 = o.crypto.crc32Table, r3 = -1;
        "string" == typeof e2 && (e2 = o.buffer.toBuffer(e2));
        for (var n2 = 0; n2 < e2.length; n2++)
          r3 = r3 >>> 8 ^ t2[255 & (r3 ^ e2.readUInt8(n2))];
        return (-1 ^ r3) >>> 0;
      }, hmac: function(e2, t2, r3, n2) {
        return r3 || (r3 = "binary"), "buffer" === r3 && (r3 = void 0), n2 || (n2 = "sha256"), "string" == typeof t2 && (t2 = o.buffer.toBuffer(t2)), o.crypto.lib.createHmac(n2, e2).update(t2).digest(r3);
      }, md5: function(e2, t2, r3) {
        return o.crypto.hash("md5", e2, t2, r3);
      }, sha256: function(e2, t2, r3) {
        return o.crypto.hash("sha256", e2, t2, r3);
      }, hash: function(e2, t2, r3, n2) {
        var i2 = o.crypto.createHash(e2);
        r3 || (r3 = "binary"), "buffer" === r3 && (r3 = void 0), "string" == typeof t2 && (t2 = o.buffer.toBuffer(t2));
        var s = o.arraySliceFn(t2), a = o.Buffer.isBuffer(t2);
        if (o.isBrowser() && "undefined" != typeof ArrayBuffer && t2 && t2.buffer instanceof ArrayBuffer && (a = true), n2 && "object" == typeof t2 && "function" == typeof t2.on && !a)
          t2.on("data", function(e3) {
            i2.update(e3);
          }), t2.on("error", function(e3) {
            n2(e3);
          }), t2.on("end", function() {
            n2(null, i2.digest(r3));
          });
        else {
          if (!n2 || !s || a || "undefined" == typeof FileReader) {
            o.isBrowser() && "object" == typeof t2 && !a && (t2 = new o.Buffer(new Uint8Array(t2)));
            var u = i2.update(t2).digest(r3);
            return n2 && n2(null, u), u;
          }
          var c = 0, l = new FileReader();
          l.onerror = function() {
            n2(new Error("Failed to read data."));
          }, l.onload = function() {
            var e3 = new o.Buffer(new Uint8Array(l.result));
            i2.update(e3), c += e3.length, l._continueReading();
          }, l._continueReading = function() {
            if (c >= t2.size)
              return void n2(null, i2.digest(r3));
            var e3 = c + 524288;
            e3 > t2.size && (e3 = t2.size), l.readAsArrayBuffer(s.call(t2, c, e3));
          }, l._continueReading();
        }
      }, toHex: function(e2) {
        for (var t2 = [], r3 = 0; r3 < e2.length; r3++)
          t2.push(("0" + e2.charCodeAt(r3).toString(16)).substr(-2, 2));
        return t2.join("");
      }, createHash: function(e2) {
        return o.crypto.lib.createHash(e2);
      }}, abort: {}, each: function(e2, t2) {
        for (var r3 in e2)
          if (Object.prototype.hasOwnProperty.call(e2, r3)) {
            var n2 = t2.call(this, r3, e2[r3]);
            if (n2 === o.abort)
              break;
          }
      }, arrayEach: function(e2, t2) {
        for (var r3 in e2)
          if (Object.prototype.hasOwnProperty.call(e2, r3)) {
            var n2 = t2.call(this, e2[r3], parseInt(r3, 10));
            if (n2 === o.abort)
              break;
          }
      }, update: function(e2, t2) {
        return o.each(t2, function(t3, r3) {
          e2[t3] = r3;
        }), e2;
      }, merge: function(e2, t2) {
        return o.update(o.copy(e2), t2);
      }, copy: function(e2) {
        if (null === e2 || void 0 === e2)
          return e2;
        var t2 = {};
        for (var r3 in e2)
          t2[r3] = e2[r3];
        return t2;
      }, isEmpty: function(e2) {
        for (var t2 in e2)
          if (Object.prototype.hasOwnProperty.call(e2, t2))
            return false;
        return true;
      }, arraySliceFn: function(e2) {
        var t2 = e2.slice || e2.webkitSlice || e2.mozSlice;
        return "function" == typeof t2 ? t2 : null;
      }, isType: function(e2, t2) {
        return "function" == typeof t2 && (t2 = o.typeName(t2)), Object.prototype.toString.call(e2) === "[object " + t2 + "]";
      }, typeName: function(e2) {
        if (Object.prototype.hasOwnProperty.call(e2, "name"))
          return e2.name;
        var t2 = e2.toString(), r3 = t2.match(/^\s*function (.+)\(/);
        return r3 ? r3[1] : t2;
      }, error: function(e2, t2) {
        var r3 = null;
        return "string" == typeof e2.message && "" !== e2.message && ("string" == typeof t2 || t2 && t2.message) && (r3 = o.copy(e2), r3.message = e2.message), e2.message = e2.message || null, "string" == typeof t2 ? e2.message = t2 : "object" == typeof t2 && null !== t2 && (o.update(e2, t2), t2.message && (e2.message = t2.message), (t2.code || t2.name) && (e2.code = t2.code || t2.name), t2.stack && (e2.stack = t2.stack)), "function" == typeof Object.defineProperty && (Object.defineProperty(e2, "name", {writable: true, enumerable: false}), Object.defineProperty(e2, "message", {enumerable: true})), e2.name = String(t2 && t2.name || e2.name || e2.code || "Error"), e2.time = new Date(), r3 && (e2.originalError = r3), e2;
      }, inherit: function(e2, t2) {
        var r3 = null;
        if (void 0 === t2)
          t2 = e2, e2 = Object, r3 = {};
        else {
          var n2 = function() {
          };
          n2.prototype = e2.prototype, r3 = new n2();
        }
        return t2.constructor === Object && (t2.constructor = function() {
          if (e2 !== Object)
            return e2.apply(this, arguments);
        }), t2.constructor.prototype = r3, o.update(t2.constructor.prototype, t2), t2.constructor.__super__ = e2, t2.constructor;
      }, mixin: function() {
        for (var e2 = arguments[0], t2 = 1; t2 < arguments.length; t2++)
          for (var r3 in arguments[t2].prototype) {
            var n2 = arguments[t2].prototype[r3];
            "constructor" !== r3 && (e2.prototype[r3] = n2);
          }
        return e2;
      }, hideProperties: function(e2, t2) {
        "function" == typeof Object.defineProperty && o.arrayEach(t2, function(t3) {
          Object.defineProperty(e2, t3, {enumerable: false, writable: true, configurable: true});
        });
      }, property: function(e2, t2, r3, n2, i2) {
        var o2 = {configurable: true, enumerable: void 0 === n2 || n2};
        "function" != typeof r3 || i2 ? (o2.value = r3, o2.writable = true) : o2.get = r3, Object.defineProperty(e2, t2, o2);
      }, memoizedProperty: function(e2, t2, r3, n2) {
        var i2 = null;
        o.property(e2, t2, function() {
          return null === i2 && (i2 = r3()), i2;
        }, n2);
      }, hoistPayloadMember: function(e2) {
        var t2 = e2.request, r3 = t2.operation, n2 = t2.service.api.operations[r3], i2 = n2.output;
        if (i2.payload && !n2.hasEventOutput) {
          var s = i2.members[i2.payload], a = e2.data[i2.payload];
          "structure" === s.type && o.each(a, function(t3, r4) {
            o.property(e2.data, t3, r4, false);
          });
        }
      }, computeSha256: function(t2, r3) {
        if (o.isNode()) {
          var n2 = o.stream.Stream, i2 = e("fs");
          if ("function" == typeof n2 && t2 instanceof n2) {
            if ("string" != typeof t2.path)
              return r3(new Error("Non-file stream objects are not supported with SigV4"));
            var s = {};
            "number" == typeof t2.start && (s.start = t2.start), "number" == typeof t2.end && (s.end = t2.end), t2 = i2.createReadStream(t2.path, s);
          }
        }
        o.crypto.sha256(t2, "hex", function(e2, t3) {
          e2 ? r3(e2) : r3(null, t3);
        });
      }, isClockSkewed: function(e2) {
        if (e2)
          return o.property(i.config, "isClockSkewed", Math.abs(new Date().getTime() - e2) >= 3e5, false), i.config.isClockSkewed;
      }, applyClockOffset: function(e2) {
        e2 && (i.config.systemClockOffset = e2 - new Date().getTime());
      }, extractRequestId: function(e2) {
        var t2 = e2.httpResponse.headers["x-amz-request-id"] || e2.httpResponse.headers["x-amzn-requestid"];
        !t2 && e2.data && e2.data.ResponseMetadata && (t2 = e2.data.ResponseMetadata.RequestId), t2 && (e2.requestId = t2), e2.error && (e2.error.requestId = t2);
      }, addPromises: function(e2, t2) {
        var r3 = false;
        void 0 === t2 && i && i.config && (t2 = i.config.getPromisesDependency()), void 0 === t2 && "undefined" != typeof Promise && (t2 = Promise), "function" != typeof t2 && (r3 = true), Array.isArray(e2) || (e2 = [e2]);
        for (var n2 = 0; n2 < e2.length; n2++) {
          var o2 = e2[n2];
          r3 ? o2.deletePromisesFromClass && o2.deletePromisesFromClass() : o2.addPromisesToClass && o2.addPromisesToClass(t2);
        }
      }, promisifyMethod: function(e2, t2) {
        return function() {
          var r3 = this, n2 = Array.prototype.slice.call(arguments);
          return new t2(function(t3, i2) {
            n2.push(function(e3, r4) {
              e3 ? i2(e3) : t3(r4);
            }), r3[e2].apply(r3, n2);
          });
        };
      }, isDualstackAvailable: function(t2) {
        if (!t2)
          return false;
        var r3 = e("../apis/metadata.json");
        return "string" != typeof t2 && (t2 = t2.serviceIdentifier), !("string" != typeof t2 || !r3.hasOwnProperty(t2)) && !!r3[t2].dualstackAvailable;
      }, calculateRetryDelay: function(e2, t2, r3) {
        t2 || (t2 = {});
        var n2 = t2.customBackoff || null;
        if ("function" == typeof n2)
          return n2(e2, r3);
        var i2 = "number" == typeof t2.base ? t2.base : 100;
        return Math.random() * (Math.pow(2, e2) * i2);
      }, handleRequestWithRetries: function(e2, t2, r3) {
        t2 || (t2 = {});
        var n2 = i.HttpClient.getInstance(), s = t2.httpOptions || {}, a = 0, u = function(e3) {
          var n3 = t2.maxRetries || 0;
          e3 && "TimeoutError" === e3.code && (e3.retryable = true);
          var i2 = o.calculateRetryDelay(a, t2.retryDelayOptions, e3);
          e3 && e3.retryable && a < n3 && i2 >= 0 ? (a++, setTimeout(c, i2 + (e3.retryAfter || 0))) : r3(e3);
        }, c = function() {
          var t3 = "";
          n2.handleRequest(e2, s, function(e3) {
            e3.on("data", function(e4) {
              t3 += e4.toString();
            }), e3.on("end", function() {
              var n3 = e3.statusCode;
              if (n3 < 300)
                r3(null, t3);
              else {
                var i2 = 1e3 * parseInt(e3.headers["retry-after"], 10) || 0, s2 = o.error(new Error(), {statusCode: n3, retryable: n3 >= 500 || 429 === n3});
                i2 && s2.retryable && (s2.retryAfter = i2), u(s2);
              }
            });
          }, u);
        };
        i.util.defer(c);
      }, uuid: {v4: function() {
        return e("uuid").v4();
      }}, convertPayloadToString: function(e2) {
        var t2 = e2.request, r3 = t2.operation, n2 = t2.service.api.operations[r3].output || {};
        n2.payload && e2.data[n2.payload] && (e2.data[n2.payload] = e2.data[n2.payload].toString());
      }, defer: function(e2) {
        "object" == typeof r2 && "function" == typeof r2.nextTick ? r2.nextTick(e2) : "function" == typeof n ? n(e2) : setTimeout(e2, 0);
      }, getRequestPayloadShape: function(e2) {
        var t2 = e2.service.api.operations;
        if (t2) {
          var r3 = (t2 || {})[e2.operation];
          if (r3 && r3.input && r3.input.payload)
            return r3.input.members[r3.input.payload];
        }
      }, getProfilesFromSharedConfig: function(e2, t2) {
        var n2 = {}, i2 = {};
        if (r2.env[o.configOptInEnv])
          var i2 = e2.loadFrom({isConfig: true, filename: r2.env[o.sharedConfigFileEnv]});
        for (var s = e2.loadFrom({filename: t2 || r2.env[o.configOptInEnv] && r2.env[o.sharedCredentialsFileEnv]}), a = 0, u = Object.keys(i2); a < u.length; a++)
          n2[u[a]] = i2[u[a]];
        for (var a = 0, u = Object.keys(s); a < u.length; a++)
          n2[u[a]] = s[u[a]];
        return n2;
      }, ARN: {validate: function(e2) {
        return e2 && 0 === e2.indexOf("arn:") && e2.split(":").length >= 6;
      }, parse: function(e2) {
        var t2 = e2.split(":");
        return {partition: t2[1], service: t2[2], region: t2[3], accountId: t2[4], resource: t2.slice(5).join(":")};
      }, build: function(e2) {
        if (void 0 === e2.service || void 0 === e2.region || void 0 === e2.accountId || void 0 === e2.resource)
          throw o.error(new Error("Input ARN object is invalid"));
        return "arn:" + (e2.partition || "aws") + ":" + e2.service + ":" + e2.region + ":" + e2.accountId + ":" + e2.resource;
      }}, defaultProfile: "default", configOptInEnv: "AWS_SDK_LOAD_CONFIG", sharedCredentialsFileEnv: "AWS_SHARED_CREDENTIALS_FILE", sharedConfigFileEnv: "AWS_CONFIG_FILE", imdsDisabledEnv: "AWS_EC2_METADATA_DISABLED"};
      t.exports = o;
    }).call(this, e("_process"), e("timers").setImmediate);
  }, {"../apis/metadata.json": 26, "./core": 39, _process: 8, fs: 2, timers: 16, uuid: 21}], 37: [function(e, t, r) {
    var n = e("./core");
    e("./credentials"), e("./credentials/credential_provider_chain");
    var i;
    n.Config = n.util.inherit({constructor: function(e2) {
      void 0 === e2 && (e2 = {}), e2 = this.extractCredentials(e2), n.util.each.call(this, this.keys, function(t2, r2) {
        this.set(t2, e2[t2], r2);
      });
    }, getCredentials: function(e2) {
      function t2(t3) {
        e2(t3, t3 ? null : i2.credentials);
      }
      function r2(e3, t3) {
        return new n.util.error(t3 || new Error(), {code: "CredentialsError", message: e3, name: "CredentialsError"});
      }
      var i2 = this;
      i2.credentials ? "function" == typeof i2.credentials.get ? function() {
        i2.credentials.get(function(e3) {
          e3 && (e3 = r2("Could not load credentials from " + i2.credentials.constructor.name, e3)), t2(e3);
        });
      }() : function() {
        var e3 = null;
        i2.credentials.accessKeyId && i2.credentials.secretAccessKey || (e3 = r2("Missing credentials")), t2(e3);
      }() : i2.credentialProvider ? i2.credentialProvider.resolve(function(e3, n2) {
        e3 && (e3 = r2("Could not load credentials from any providers", e3)), i2.credentials = n2, t2(e3);
      }) : t2(r2("No credentials to load"));
    }, update: function(e2, t2) {
      t2 = t2 || false, e2 = this.extractCredentials(e2), n.util.each.call(this, e2, function(e3, r2) {
        (t2 || Object.prototype.hasOwnProperty.call(this.keys, e3) || n.Service.hasService(e3)) && this.set(e3, r2);
      });
    }, loadFromPath: function(e2) {
      this.clear();
      var t2 = JSON.parse(n.util.readFileSync(e2)), r2 = new n.FileSystemCredentials(e2), i2 = new n.CredentialProviderChain();
      return i2.providers.unshift(r2), i2.resolve(function(e3, r3) {
        if (e3)
          throw e3;
        t2.credentials = r3;
      }), this.constructor(t2), this;
    }, clear: function() {
      n.util.each.call(this, this.keys, function(e2) {
        delete this[e2];
      }), this.set("credentials", void 0), this.set("credentialProvider", void 0);
    }, set: function(e2, t2, r2) {
      void 0 === t2 ? (void 0 === r2 && (r2 = this.keys[e2]), this[e2] = "function" == typeof r2 ? r2.call(this) : r2) : "httpOptions" === e2 && this[e2] ? this[e2] = n.util.merge(this[e2], t2) : this[e2] = t2;
    }, keys: {credentials: null, credentialProvider: null, region: null, logger: null, apiVersions: {}, apiVersion: null, endpoint: void 0, httpOptions: {timeout: 12e4}, maxRetries: void 0, maxRedirects: 10, paramValidation: true, sslEnabled: true, s3ForcePathStyle: false, s3BucketEndpoint: false, s3DisableBodySigning: true, s3UsEast1RegionalEndpoint: "legacy", s3UseArnRegion: void 0, computeChecksums: true, convertResponseTypes: true, correctClockSkew: false, customUserAgent: null, dynamoDbCrc32: true, systemClockOffset: 0, signatureVersion: null, signatureCache: true, retryDelayOptions: {}, useAccelerateEndpoint: false, clientSideMonitoring: false, endpointDiscoveryEnabled: void 0, endpointCacheSize: 1e3, hostPrefixEnabled: true, stsRegionalEndpoints: "legacy"}, extractCredentials: function(e2) {
      return e2.accessKeyId && e2.secretAccessKey && (e2 = n.util.copy(e2), e2.credentials = new n.Credentials(e2)), e2;
    }, setPromisesDependency: function(e2) {
      i = e2, null === e2 && "function" == typeof Promise && (i = Promise);
      var t2 = [n.Request, n.Credentials, n.CredentialProviderChain];
      n.S3 && (t2.push(n.S3), n.S3.ManagedUpload && t2.push(n.S3.ManagedUpload)), n.util.addPromises(t2, i);
    }, getPromisesDependency: function() {
      return i;
    }}), n.config = new n.Config();
  }, {"./core": 39, "./credentials": 40, "./credentials/credential_provider_chain": 43}], 43: [function(e, t, r) {
    var n = e("../core");
    n.CredentialProviderChain = n.util.inherit(n.Credentials, {constructor: function(e2) {
      this.providers = e2 || n.CredentialProviderChain.defaultProviders.slice(0), this.resolveCallbacks = [];
    }, resolve: function(e2) {
      function t2(e3, s) {
        if (!e3 && s || i === o.length)
          return n.util.arrayEach(r2.resolveCallbacks, function(t3) {
            t3(e3, s);
          }), void (r2.resolveCallbacks.length = 0);
        var a = o[i++];
        s = "function" == typeof a ? a.call() : a, s.get ? s.get(function(e4) {
          t2(e4, e4 ? null : s);
        }) : t2(null, s);
      }
      var r2 = this;
      if (0 === r2.providers.length)
        return e2(new Error("No providers")), r2;
      if (1 === r2.resolveCallbacks.push(e2)) {
        var i = 0, o = r2.providers.slice(0);
        t2();
      }
      return r2;
    }}), n.CredentialProviderChain.defaultProviders = [], n.CredentialProviderChain.addPromisesToClass = function(e2) {
      this.prototype.resolvePromise = n.util.promisifyMethod("resolve", e2);
    }, n.CredentialProviderChain.deletePromisesFromClass = function() {
      delete this.prototype.resolvePromise;
    }, n.util.addPromises(n.CredentialProviderChain);
  }, {"../core": 39}], 40: [function(e, t, r) {
    var n = e("./core");
    n.Credentials = n.util.inherit({constructor: function() {
      if (n.util.hideProperties(this, ["secretAccessKey"]), this.expired = false, this.expireTime = null, this.refreshCallbacks = [], 1 === arguments.length && "object" == typeof arguments[0]) {
        var e2 = arguments[0].credentials || arguments[0];
        this.accessKeyId = e2.accessKeyId, this.secretAccessKey = e2.secretAccessKey, this.sessionToken = e2.sessionToken;
      } else
        this.accessKeyId = arguments[0], this.secretAccessKey = arguments[1], this.sessionToken = arguments[2];
    }, expiryWindow: 15, needsRefresh: function() {
      var e2 = n.util.date.getDate().getTime(), t2 = new Date(e2 + 1e3 * this.expiryWindow);
      return !!(this.expireTime && t2 > this.expireTime) || (this.expired || !this.accessKeyId || !this.secretAccessKey);
    }, get: function(e2) {
      var t2 = this;
      this.needsRefresh() ? this.refresh(function(r2) {
        r2 || (t2.expired = false), e2 && e2(r2);
      }) : e2 && e2();
    }, refresh: function(e2) {
      this.expired = false, e2();
    }, coalesceRefresh: function(e2, t2) {
      var r2 = this;
      1 === r2.refreshCallbacks.push(e2) && r2.load(function(e3) {
        n.util.arrayEach(r2.refreshCallbacks, function(r3) {
          t2 ? r3(e3) : n.util.defer(function() {
            r3(e3);
          });
        }), r2.refreshCallbacks.length = 0;
      });
    }, load: function(e2) {
      e2();
    }}), n.Credentials.addPromisesToClass = function(e2) {
      this.prototype.getPromise = n.util.promisifyMethod("get", e2), this.prototype.refreshPromise = n.util.promisifyMethod("refresh", e2);
    }, n.Credentials.deletePromisesFromClass = function() {
      delete this.prototype.getPromise, delete this.prototype.refreshPromise;
    }, n.util.addPromises(n.Credentials);
  }, {"./core": 39}], 27: [function(e, t, r) {
    function n(e2, t2) {
      if (!n.services.hasOwnProperty(e2))
        throw new Error("InvalidService: Failed to load api for " + e2);
      return n.services[e2][t2];
    }
    n.services = {}, t.exports = n;
  }, {}], 26: [function(e, t, r) {
    t.exports = {acm: {name: "ACM", cors: true}, apigateway: {name: "APIGateway", cors: true}, applicationautoscaling: {prefix: "application-autoscaling", name: "ApplicationAutoScaling", cors: true}, appstream: {name: "AppStream"}, autoscaling: {name: "AutoScaling", cors: true}, batch: {name: "Batch"}, budgets: {name: "Budgets"}, clouddirectory: {name: "CloudDirectory", versions: ["2016-05-10*"]}, cloudformation: {name: "CloudFormation", cors: true}, cloudfront: {name: "CloudFront", versions: ["2013-05-12*", "2013-11-11*", "2014-05-31*", "2014-10-21*", "2014-11-06*", "2015-04-17*", "2015-07-27*", "2015-09-17*", "2016-01-13*", "2016-01-28*", "2016-08-01*", "2016-08-20*", "2016-09-07*", "2016-09-29*", "2016-11-25*", "2017-03-25*", "2017-10-30*", "2018-06-18*", "2018-11-05*"], cors: true}, cloudhsm: {name: "CloudHSM", cors: true}, cloudsearch: {name: "CloudSearch"}, cloudsearchdomain: {name: "CloudSearchDomain"}, cloudtrail: {name: "CloudTrail", cors: true}, cloudwatch: {prefix: "monitoring", name: "CloudWatch", cors: true}, cloudwatchevents: {prefix: "events", name: "CloudWatchEvents", versions: ["2014-02-03*"], cors: true}, cloudwatchlogs: {prefix: "logs", name: "CloudWatchLogs", cors: true}, codebuild: {name: "CodeBuild", cors: true}, codecommit: {name: "CodeCommit", cors: true}, codedeploy: {name: "CodeDeploy", cors: true}, codepipeline: {name: "CodePipeline", cors: true}, cognitoidentity: {prefix: "cognito-identity", name: "CognitoIdentity", cors: true}, cognitoidentityserviceprovider: {prefix: "cognito-idp", name: "CognitoIdentityServiceProvider", cors: true}, cognitosync: {prefix: "cognito-sync", name: "CognitoSync", cors: true}, configservice: {prefix: "config", name: "ConfigService", cors: true}, cur: {name: "CUR", cors: true}, datapipeline: {name: "DataPipeline"}, devicefarm: {name: "DeviceFarm", cors: true}, directconnect: {name: "DirectConnect", cors: true}, directoryservice: {prefix: "ds", name: "DirectoryService"}, discovery: {name: "Discovery"}, dms: {name: "DMS"}, dynamodb: {name: "DynamoDB", cors: true}, dynamodbstreams: {prefix: "streams.dynamodb", name: "DynamoDBStreams", cors: true}, ec2: {name: "EC2", versions: ["2013-06-15*", "2013-10-15*", "2014-02-01*", "2014-05-01*", "2014-06-15*", "2014-09-01*", "2014-10-01*", "2015-03-01*", "2015-04-15*", "2015-10-01*", "2016-04-01*", "2016-09-15*"], cors: true}, ecr: {name: "ECR", cors: true}, ecs: {name: "ECS", cors: true}, efs: {prefix: "elasticfilesystem", name: "EFS", cors: true}, elasticache: {name: "ElastiCache", versions: ["2012-11-15*", "2014-03-24*", "2014-07-15*", "2014-09-30*"], cors: true}, elasticbeanstalk: {name: "ElasticBeanstalk", cors: true}, elb: {prefix: "elasticloadbalancing", name: "ELB", cors: true}, elbv2: {prefix: "elasticloadbalancingv2", name: "ELBv2", cors: true}, emr: {prefix: "elasticmapreduce", name: "EMR", cors: true}, es: {name: "ES"}, elastictranscoder: {name: "ElasticTranscoder", cors: true}, firehose: {name: "Firehose", cors: true}, gamelift: {name: "GameLift", cors: true}, glacier: {name: "Glacier"}, health: {name: "Health"}, iam: {name: "IAM", cors: true}, importexport: {name: "ImportExport"}, inspector: {name: "Inspector", versions: ["2015-08-18*"], cors: true}, iot: {name: "Iot", cors: true}, iotdata: {prefix: "iot-data", name: "IotData", cors: true}, kinesis: {name: "Kinesis", cors: true}, kinesisanalytics: {name: "KinesisAnalytics"}, kms: {name: "KMS", cors: true}, lambda: {name: "Lambda", cors: true}, lexruntime: {prefix: "runtime.lex", name: "LexRuntime", cors: true}, lightsail: {name: "Lightsail"}, machinelearning: {name: "MachineLearning", cors: true}, marketplacecommerceanalytics: {name: "MarketplaceCommerceAnalytics", cors: true}, marketplacemetering: {prefix: "meteringmarketplace", name: "MarketplaceMetering"}, mturk: {prefix: "mturk-requester", name: "MTurk", cors: true}, mobileanalytics: {name: "MobileAnalytics", cors: true}, opsworks: {name: "OpsWorks", cors: true}, opsworkscm: {name: "OpsWorksCM"}, organizations: {name: "Organizations"}, pinpoint: {name: "Pinpoint"}, polly: {name: "Polly", cors: true}, rds: {name: "RDS", versions: ["2014-09-01*"], cors: true}, redshift: {name: "Redshift", cors: true}, rekognition: {name: "Rekognition", cors: true}, resourcegroupstaggingapi: {name: "ResourceGroupsTaggingAPI"}, route53: {name: "Route53", cors: true}, route53domains: {name: "Route53Domains", cors: true}, s3: {name: "S3", dualstackAvailable: true, cors: true}, s3control: {name: "S3Control", dualstackAvailable: true, xmlNoDefaultLists: true}, servicecatalog: {name: "ServiceCatalog", cors: true}, ses: {prefix: "email", name: "SES", cors: true}, shield: {name: "Shield"}, simpledb: {prefix: "sdb", name: "SimpleDB"}, sms: {name: "SMS"}, snowball: {name: "Snowball"}, sns: {name: "SNS", cors: true}, sqs: {name: "SQS", cors: true}, ssm: {name: "SSM", cors: true}, storagegateway: {name: "StorageGateway", cors: true}, stepfunctions: {prefix: "states", name: "StepFunctions"}, sts: {name: "STS", cors: true}, support: {name: "Support"}, swf: {name: "SWF"}, xray: {name: "XRay", cors: true}, waf: {name: "WAF", cors: true}, wafregional: {prefix: "waf-regional", name: "WAFRegional"}, workdocs: {name: "WorkDocs", cors: true}, workspaces: {name: "WorkSpaces"}, codestar: {name: "CodeStar"}, lexmodelbuildingservice: {prefix: "lex-models", name: "LexModelBuildingService", cors: true}, marketplaceentitlementservice: {prefix: "entitlement.marketplace", name: "MarketplaceEntitlementService"}, athena: {name: "Athena"}, greengrass: {name: "Greengrass"}, dax: {name: "DAX"}, migrationhub: {prefix: "AWSMigrationHub", name: "MigrationHub"}, cloudhsmv2: {name: "CloudHSMV2"}, glue: {name: "Glue"}, mobile: {name: "Mobile"}, pricing: {name: "Pricing", cors: true}, costexplorer: {prefix: "ce", name: "CostExplorer", cors: true}, mediaconvert: {name: "MediaConvert"}, medialive: {name: "MediaLive"}, mediapackage: {name: "MediaPackage"}, mediastore: {name: "MediaStore"}, mediastoredata: {prefix: "mediastore-data", name: "MediaStoreData", cors: true}, appsync: {name: "AppSync"}, guardduty: {name: "GuardDuty"}, mq: {name: "MQ"}, comprehend: {name: "Comprehend", cors: true}, iotjobsdataplane: {prefix: "iot-jobs-data", name: "IoTJobsDataPlane"}, kinesisvideoarchivedmedia: {prefix: "kinesis-video-archived-media", name: "KinesisVideoArchivedMedia", cors: true}, kinesisvideomedia: {prefix: "kinesis-video-media", name: "KinesisVideoMedia", cors: true}, kinesisvideo: {name: "KinesisVideo", cors: true}, sagemakerruntime: {prefix: "runtime.sagemaker", name: "SageMakerRuntime"}, sagemaker: {name: "SageMaker"}, translate: {name: "Translate", cors: true}, resourcegroups: {prefix: "resource-groups", name: "ResourceGroups", cors: true}, alexaforbusiness: {name: "AlexaForBusiness"}, cloud9: {name: "Cloud9"}, serverlessapplicationrepository: {prefix: "serverlessrepo", name: "ServerlessApplicationRepository"}, servicediscovery: {name: "ServiceDiscovery"}, workmail: {name: "WorkMail"}, autoscalingplans: {prefix: "autoscaling-plans", name: "AutoScalingPlans"}, transcribeservice: {prefix: "transcribe", name: "TranscribeService"}, connect: {name: "Connect", cors: true}, acmpca: {prefix: "acm-pca", name: "ACMPCA"}, fms: {name: "FMS"}, secretsmanager: {name: "SecretsManager", cors: true}, iotanalytics: {name: "IoTAnalytics", cors: true}, iot1clickdevicesservice: {prefix: "iot1click-devices", name: "IoT1ClickDevicesService"}, iot1clickprojects: {prefix: "iot1click-projects", name: "IoT1ClickProjects"}, pi: {name: "PI"}, neptune: {name: "Neptune"}, mediatailor: {name: "MediaTailor"}, eks: {name: "EKS"}, macie: {name: "Macie"}, dlm: {name: "DLM"}, signer: {name: "Signer"}, chime: {name: "Chime"}, pinpointemail: {prefix: "pinpoint-email", name: "PinpointEmail"}, ram: {name: "RAM"}, route53resolver: {name: "Route53Resolver"}, pinpointsmsvoice: {prefix: "sms-voice", name: "PinpointSMSVoice"}, quicksight: {name: "QuickSight"}, rdsdataservice: {prefix: "rds-data", name: "RDSDataService"}, amplify: {name: "Amplify"}, datasync: {name: "DataSync"}, robomaker: {name: "RoboMaker"}, transfer: {name: "Transfer"}, globalaccelerator: {name: "GlobalAccelerator"}, comprehendmedical: {name: "ComprehendMedical", cors: true}, kinesisanalyticsv2: {name: "KinesisAnalyticsV2"}, mediaconnect: {name: "MediaConnect"}, fsx: {name: "FSx"}, securityhub: {name: "SecurityHub"}, appmesh: {name: "AppMesh", versions: ["2018-10-01*"]}, licensemanager: {prefix: "license-manager", name: "LicenseManager"}, kafka: {name: "Kafka"}, apigatewaymanagementapi: {name: "ApiGatewayManagementApi"}, apigatewayv2: {name: "ApiGatewayV2"}, docdb: {name: "DocDB"}, backup: {name: "Backup"}, worklink: {name: "WorkLink"}, textract: {name: "Textract"}, managedblockchain: {name: "ManagedBlockchain"}, mediapackagevod: {prefix: "mediapackage-vod", name: "MediaPackageVod"}, groundstation: {name: "GroundStation"}, iotthingsgraph: {name: "IoTThingsGraph"}, iotevents: {name: "IoTEvents"}, ioteventsdata: {prefix: "iotevents-data", name: "IoTEventsData"}, personalize: {name: "Personalize", cors: true}, personalizeevents: {prefix: "personalize-events", name: "PersonalizeEvents", cors: true}, personalizeruntime: {prefix: "personalize-runtime", name: "PersonalizeRuntime", cors: true}, applicationinsights: {prefix: "application-insights", name: "ApplicationInsights"}, servicequotas: {prefix: "service-quotas", name: "ServiceQuotas"}, ec2instanceconnect: {prefix: "ec2-instance-connect", name: "EC2InstanceConnect"}, eventbridge: {name: "EventBridge"}, lakeformation: {name: "LakeFormation"}, forecastservice: {prefix: "forecast", name: "ForecastService", cors: true}, forecastqueryservice: {prefix: "forecastquery", name: "ForecastQueryService", cors: true}, qldb: {name: "QLDB"}, qldbsession: {prefix: "qldb-session", name: "QLDBSession"}, workmailmessageflow: {name: "WorkMailMessageFlow"}, codestarnotifications: {prefix: "codestar-notifications", name: "CodeStarNotifications"}, savingsplans: {name: "SavingsPlans"}, sso: {name: "SSO"}, ssooidc: {prefix: "sso-oidc", name: "SSOOIDC"}, marketplacecatalog: {prefix: "marketplace-catalog", name: "MarketplaceCatalog"}, dataexchange: {name: "DataExchange"}, sesv2: {name: "SESV2"}, migrationhubconfig: {prefix: "migrationhub-config", name: "MigrationHubConfig"}, connectparticipant: {name: "ConnectParticipant"}, appconfig: {name: "AppConfig"}, iotsecuretunneling: {name: "IoTSecureTunneling"}, wafv2: {name: "WAFV2"}, elasticinference: {prefix: "elastic-inference", name: "ElasticInference"}, imagebuilder: {name: "Imagebuilder"}, schemas: {name: "Schemas"}, accessanalyzer: {name: "AccessAnalyzer"}, codegurureviewer: {prefix: "codeguru-reviewer", name: "CodeGuruReviewer"}, codeguruprofiler: {name: "CodeGuruProfiler"}, computeoptimizer: {prefix: "compute-optimizer", name: "ComputeOptimizer"}, frauddetector: {name: "FraudDetector"}, kendra: {name: "Kendra"}, networkmanager: {name: "NetworkManager"}, outposts: {name: "Outposts"}, augmentedairuntime: {prefix: "sagemaker-a2i-runtime", name: "AugmentedAIRuntime"}, ebs: {name: "EBS"}, kinesisvideosignalingchannels: {prefix: "kinesis-video-signaling", name: "KinesisVideoSignalingChannels", cors: true}, detective: {name: "Detective"}, codestarconnections: {prefix: "codestar-connections", name: "CodeStarconnections"}, synthetics: {name: "Synthetics"}, iotsitewise: {name: "IoTSiteWise"}, macie2: {name: "Macie2"}, codeartifact: {name: "CodeArtifact"}, honeycode: {name: "Honeycode"}};
  }, {}], 21: [function(e, t, r) {
    var n = e("./v1"), i = e("./v4"), o = i;
    o.v1 = n, o.v4 = i, t.exports = o;
  }, {"./v1": 24, "./v4": 25}], 25: [function(e, t, r) {
    function n(e2, t2, r2) {
      var n2 = t2 && r2 || 0;
      "string" == typeof e2 && (t2 = "binary" === e2 ? new Array(16) : null, e2 = null), e2 = e2 || {};
      var s = e2.random || (e2.rng || i)();
      if (s[6] = 15 & s[6] | 64, s[8] = 63 & s[8] | 128, t2)
        for (var a = 0; a < 16; ++a)
          t2[n2 + a] = s[a];
      return t2 || o(s);
    }
    var i = e("./lib/rng"), o = e("./lib/bytesToUuid");
    t.exports = n;
  }, {"./lib/bytesToUuid": 22, "./lib/rng": 23}], 24: [function(e, t, r) {
    function n(e2, t2, r2) {
      var n2 = t2 && r2 || 0, l = t2 || [];
      e2 = e2 || {};
      var h = e2.node || i, p = void 0 !== e2.clockseq ? e2.clockseq : o;
      if (null == h || null == p) {
        var f = s();
        null == h && (h = i = [1 | f[0], f[1], f[2], f[3], f[4], f[5]]), null == p && (p = o = 16383 & (f[6] << 8 | f[7]));
      }
      var d = void 0 !== e2.msecs ? e2.msecs : new Date().getTime(), m = void 0 !== e2.nsecs ? e2.nsecs : c + 1, v = d - u + (m - c) / 1e4;
      if (v < 0 && void 0 === e2.clockseq && (p = p + 1 & 16383), (v < 0 || d > u) && void 0 === e2.nsecs && (m = 0), m >= 1e4)
        throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
      u = d, c = m, o = p, d += 122192928e5;
      var g = (1e4 * (268435455 & d) + m) % 4294967296;
      l[n2++] = g >>> 24 & 255, l[n2++] = g >>> 16 & 255, l[n2++] = g >>> 8 & 255, l[n2++] = 255 & g;
      var y = d / 4294967296 * 1e4 & 268435455;
      l[n2++] = y >>> 8 & 255, l[n2++] = 255 & y, l[n2++] = y >>> 24 & 15 | 16, l[n2++] = y >>> 16 & 255, l[n2++] = p >>> 8 | 128, l[n2++] = 255 & p;
      for (var b = 0; b < 6; ++b)
        l[n2 + b] = h[b];
      return t2 || a(l);
    }
    var i, o, s = e("./lib/rng"), a = e("./lib/bytesToUuid"), u = 0, c = 0;
    t.exports = n;
  }, {"./lib/bytesToUuid": 22, "./lib/rng": 23}], 23: [function(e, t, r) {
    var n = "undefined" != typeof crypto && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || "undefined" != typeof msCrypto && "function" == typeof window.msCrypto.getRandomValues && msCrypto.getRandomValues.bind(msCrypto);
    if (n) {
      var i = new Uint8Array(16);
      t.exports = function() {
        return n(i), i;
      };
    } else {
      var o = new Array(16);
      t.exports = function() {
        for (var e2, t2 = 0; t2 < 16; t2++)
          0 == (3 & t2) && (e2 = 4294967296 * Math.random()), o[t2] = e2 >>> ((3 & t2) << 3) & 255;
        return o;
      };
    }
  }, {}], 22: [function(e, t, r) {
    function n(e2, t2) {
      var r2 = t2 || 0, n2 = i;
      return [n2[e2[r2++]], n2[e2[r2++]], n2[e2[r2++]], n2[e2[r2++]], "-", n2[e2[r2++]], n2[e2[r2++]], "-", n2[e2[r2++]], n2[e2[r2++]], "-", n2[e2[r2++]], n2[e2[r2++]], "-", n2[e2[r2++]], n2[e2[r2++]], n2[e2[r2++]], n2[e2[r2++]], n2[e2[r2++]], n2[e2[r2++]]].join("");
    }
    for (var i = [], o = 0; o < 256; ++o)
      i[o] = (o + 256).toString(16).substr(1);
    t.exports = n;
  }, {}], 20: [function(e, t, r) {
    (function(t2, n) {
      function i(e2, t3) {
        var n2 = {seen: [], stylize: s};
        return arguments.length >= 3 && (n2.depth = arguments[2]), arguments.length >= 4 && (n2.colors = arguments[3]), m(t3) ? n2.showHidden = t3 : t3 && r._extend(n2, t3), E(n2.showHidden) && (n2.showHidden = false), E(n2.depth) && (n2.depth = 2), E(n2.colors) && (n2.colors = false), E(n2.customInspect) && (n2.customInspect = true), n2.colors && (n2.stylize = o), u(n2, e2, n2.depth);
      }
      function o(e2, t3) {
        var r2 = i.styles[t3];
        return r2 ? "[" + i.colors[r2][0] + "m" + e2 + "[" + i.colors[r2][1] + "m" : e2;
      }
      function s(e2, t3) {
        return e2;
      }
      function a(e2) {
        var t3 = {};
        return e2.forEach(function(e3, r2) {
          t3[e3] = true;
        }), t3;
      }
      function u(e2, t3, n2) {
        if (e2.customInspect && t3 && R(t3.inspect) && t3.inspect !== r.inspect && (!t3.constructor || t3.constructor.prototype !== t3)) {
          var i2 = t3.inspect(n2, e2);
          return b(i2) || (i2 = u(e2, i2, n2)), i2;
        }
        var o2 = c(e2, t3);
        if (o2)
          return o2;
        var s2 = Object.keys(t3), m2 = a(s2);
        if (e2.showHidden && (s2 = Object.getOwnPropertyNames(t3)), x(t3) && (s2.indexOf("message") >= 0 || s2.indexOf("description") >= 0))
          return l(t3);
        if (0 === s2.length) {
          if (R(t3)) {
            var v2 = t3.name ? ": " + t3.name : "";
            return e2.stylize("[Function" + v2 + "]", "special");
          }
          if (_(t3))
            return e2.stylize(RegExp.prototype.toString.call(t3), "regexp");
          if (C(t3))
            return e2.stylize(Date.prototype.toString.call(t3), "date");
          if (x(t3))
            return l(t3);
        }
        var g2 = "", y2 = false, w2 = ["{", "}"];
        (d(t3) && (y2 = true, w2 = ["[", "]"]), R(t3)) && (g2 = " [Function" + (t3.name ? ": " + t3.name : "") + "]");
        if (_(t3) && (g2 = " " + RegExp.prototype.toString.call(t3)), C(t3) && (g2 = " " + Date.prototype.toUTCString.call(t3)), x(t3) && (g2 = " " + l(t3)), 0 === s2.length && (!y2 || 0 == t3.length))
          return w2[0] + g2 + w2[1];
        if (n2 < 0)
          return _(t3) ? e2.stylize(RegExp.prototype.toString.call(t3), "regexp") : e2.stylize("[Object]", "special");
        e2.seen.push(t3);
        var E2;
        return E2 = y2 ? h(e2, t3, n2, m2, s2) : s2.map(function(r2) {
          return p(e2, t3, n2, m2, r2, y2);
        }), e2.seen.pop(), f(E2, g2, w2);
      }
      function c(e2, t3) {
        if (E(t3))
          return e2.stylize("undefined", "undefined");
        if (b(t3)) {
          var r2 = "'" + JSON.stringify(t3).replace(/^"|"$/g, "").replace(/'/g, "\\'").replace(/\\"/g, '"') + "'";
          return e2.stylize(r2, "string");
        }
        return y(t3) ? e2.stylize("" + t3, "number") : m(t3) ? e2.stylize("" + t3, "boolean") : v(t3) ? e2.stylize("null", "null") : void 0;
      }
      function l(e2) {
        return "[" + Error.prototype.toString.call(e2) + "]";
      }
      function h(e2, t3, r2, n2, i2) {
        for (var o2 = [], s2 = 0, a2 = t3.length; s2 < a2; ++s2)
          L(t3, String(s2)) ? o2.push(p(e2, t3, r2, n2, String(s2), true)) : o2.push("");
        return i2.forEach(function(i3) {
          i3.match(/^\d+$/) || o2.push(p(e2, t3, r2, n2, i3, true));
        }), o2;
      }
      function p(e2, t3, r2, n2, i2, o2) {
        var s2, a2, c2;
        if (c2 = Object.getOwnPropertyDescriptor(t3, i2) || {value: t3[i2]}, c2.get ? a2 = c2.set ? e2.stylize("[Getter/Setter]", "special") : e2.stylize("[Getter]", "special") : c2.set && (a2 = e2.stylize("[Setter]", "special")), L(n2, i2) || (s2 = "[" + i2 + "]"), a2 || (e2.seen.indexOf(c2.value) < 0 ? (a2 = v(r2) ? u(e2, c2.value, null) : u(e2, c2.value, r2 - 1), a2.indexOf("\n") > -1 && (a2 = o2 ? a2.split("\n").map(function(e3) {
          return "  " + e3;
        }).join("\n").substr(2) : "\n" + a2.split("\n").map(function(e3) {
          return "   " + e3;
        }).join("\n"))) : a2 = e2.stylize("[Circular]", "special")), E(s2)) {
          if (o2 && i2.match(/^\d+$/))
            return a2;
          s2 = JSON.stringify("" + i2), s2.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/) ? (s2 = s2.substr(1, s2.length - 2), s2 = e2.stylize(s2, "name")) : (s2 = s2.replace(/'/g, "\\'").replace(/\\"/g, '"').replace(/(^"|"$)/g, "'"), s2 = e2.stylize(s2, "string"));
        }
        return s2 + ": " + a2;
      }
      function f(e2, t3, r2) {
        var n2 = 0;
        return e2.reduce(function(e3, t4) {
          return n2++, t4.indexOf("\n") >= 0 && n2++, e3 + t4.replace(/\u001b\[\d\d?m/g, "").length + 1;
        }, 0) > 60 ? r2[0] + ("" === t3 ? "" : t3 + "\n ") + " " + e2.join(",\n  ") + " " + r2[1] : r2[0] + t3 + " " + e2.join(", ") + " " + r2[1];
      }
      function d(e2) {
        return Array.isArray(e2);
      }
      function m(e2) {
        return "boolean" == typeof e2;
      }
      function v(e2) {
        return null === e2;
      }
      function g(e2) {
        return null == e2;
      }
      function y(e2) {
        return "number" == typeof e2;
      }
      function b(e2) {
        return "string" == typeof e2;
      }
      function w(e2) {
        return "symbol" == typeof e2;
      }
      function E(e2) {
        return void 0 === e2;
      }
      function _(e2) {
        return S(e2) && "[object RegExp]" === T(e2);
      }
      function S(e2) {
        return "object" == typeof e2 && null !== e2;
      }
      function C(e2) {
        return S(e2) && "[object Date]" === T(e2);
      }
      function x(e2) {
        return S(e2) && ("[object Error]" === T(e2) || e2 instanceof Error);
      }
      function R(e2) {
        return "function" == typeof e2;
      }
      function A(e2) {
        return null === e2 || "boolean" == typeof e2 || "number" == typeof e2 || "string" == typeof e2 || "symbol" == typeof e2 || void 0 === e2;
      }
      function T(e2) {
        return Object.prototype.toString.call(e2);
      }
      function k(e2) {
        return e2 < 10 ? "0" + e2.toString(10) : e2.toString(10);
      }
      function I() {
        var e2 = new Date(), t3 = [k(e2.getHours()), k(e2.getMinutes()), k(e2.getSeconds())].join(":");
        return [e2.getDate(), N[e2.getMonth()], t3].join(" ");
      }
      function L(e2, t3) {
        return Object.prototype.hasOwnProperty.call(e2, t3);
      }
      var P = /%[sdj%]/g;
      r.format = function(e2) {
        if (!b(e2)) {
          for (var t3 = [], r2 = 0; r2 < arguments.length; r2++)
            t3.push(i(arguments[r2]));
          return t3.join(" ");
        }
        for (var r2 = 1, n2 = arguments, o2 = n2.length, s2 = String(e2).replace(P, function(e3) {
          if ("%%" === e3)
            return "%";
          if (r2 >= o2)
            return e3;
          switch (e3) {
            case "%s":
              return String(n2[r2++]);
            case "%d":
              return Number(n2[r2++]);
            case "%j":
              try {
                return JSON.stringify(n2[r2++]);
              } catch (e4) {
                return "[Circular]";
              }
            default:
              return e3;
          }
        }), a2 = n2[r2]; r2 < o2; a2 = n2[++r2])
          v(a2) || !S(a2) ? s2 += " " + a2 : s2 += " " + i(a2);
        return s2;
      }, r.deprecate = function(e2, i2) {
        function o2() {
          if (!s2) {
            if (t2.throwDeprecation)
              throw new Error(i2);
            t2.traceDeprecation ? console.trace(i2) : console.error(i2), s2 = true;
          }
          return e2.apply(this, arguments);
        }
        if (E(n.process))
          return function() {
            return r.deprecate(e2, i2).apply(this, arguments);
          };
        if (true === t2.noDeprecation)
          return e2;
        var s2 = false;
        return o2;
      };
      var q, O = {};
      r.debuglog = function(e2) {
        if (E(q) && (q = t2.env.NODE_DEBUG || ""), e2 = e2.toUpperCase(), !O[e2])
          if (new RegExp("\\b" + e2 + "\\b", "i").test(q)) {
            var n2 = t2.pid;
            O[e2] = function() {
              var t3 = r.format.apply(r, arguments);
              console.error("%s %d: %s", e2, n2, t3);
            };
          } else
            O[e2] = function() {
            };
        return O[e2];
      }, r.inspect = i, i.colors = {bold: [1, 22], italic: [3, 23], underline: [4, 24], inverse: [7, 27], white: [37, 39], grey: [90, 39], black: [30, 39], blue: [34, 39], cyan: [36, 39], green: [32, 39], magenta: [35, 39], red: [31, 39], yellow: [33, 39]}, i.styles = {special: "cyan", number: "yellow", boolean: "yellow", undefined: "grey", null: "bold", string: "green", date: "magenta", regexp: "red"}, r.isArray = d, r.isBoolean = m, r.isNull = v, r.isNullOrUndefined = g, r.isNumber = y, r.isString = b, r.isSymbol = w, r.isUndefined = E, r.isRegExp = _, r.isObject = S, r.isDate = C, r.isError = x, r.isFunction = R, r.isPrimitive = A, r.isBuffer = e("./support/isBuffer");
      var N = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
      r.log = function() {
        console.log("%s - %s", I(), r.format.apply(r, arguments));
      }, r.inherits = e("inherits"), r._extend = function(e2, t3) {
        if (!t3 || !S(t3))
          return e2;
        for (var r2 = Object.keys(t3), n2 = r2.length; n2--; )
          e2[r2[n2]] = t3[r2[n2]];
        return e2;
      };
    }).call(this, e("_process"), "undefined" != typeof window ? window : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {});
  }, {"./support/isBuffer": 19, _process: 8, inherits: 18}], 19: [function(e, t, r) {
    t.exports = function(e2) {
      return e2 && "object" == typeof e2 && "function" == typeof e2.copy && "function" == typeof e2.fill && "function" == typeof e2.readUInt8;
    };
  }, {}], 18: [function(e, t, r) {
    "function" == typeof Object.create ? t.exports = function(e2, t2) {
      e2.super_ = t2, e2.prototype = Object.create(t2.prototype, {constructor: {value: e2, enumerable: false, writable: true, configurable: true}});
    } : t.exports = function(e2, t2) {
      e2.super_ = t2;
      var r2 = function() {
      };
      r2.prototype = t2.prototype, e2.prototype = new r2(), e2.prototype.constructor = e2;
    };
  }, {}], 16: [function(e, t, r) {
    (function(t2, n) {
      function i(e2, t3) {
        this._id = e2, this._clearFn = t3;
      }
      var o = e("process/browser.js").nextTick, s = Function.prototype.apply, a = Array.prototype.slice, u = {}, c = 0;
      r.setTimeout = function() {
        return new i(s.call(setTimeout, window, arguments), clearTimeout);
      }, r.setInterval = function() {
        return new i(s.call(setInterval, window, arguments), clearInterval);
      }, r.clearTimeout = r.clearInterval = function(e2) {
        e2.close();
      }, i.prototype.unref = i.prototype.ref = function() {
      }, i.prototype.close = function() {
        this._clearFn.call(window, this._id);
      }, r.enroll = function(e2, t3) {
        clearTimeout(e2._idleTimeoutId), e2._idleTimeout = t3;
      }, r.unenroll = function(e2) {
        clearTimeout(e2._idleTimeoutId), e2._idleTimeout = -1;
      }, r._unrefActive = r.active = function(e2) {
        clearTimeout(e2._idleTimeoutId);
        var t3 = e2._idleTimeout;
        t3 >= 0 && (e2._idleTimeoutId = setTimeout(function() {
          e2._onTimeout && e2._onTimeout();
        }, t3));
      }, r.setImmediate = "function" == typeof t2 ? t2 : function(e2) {
        var t3 = c++, n2 = !(arguments.length < 2) && a.call(arguments, 1);
        return u[t3] = true, o(function() {
          u[t3] && (n2 ? e2.apply(null, n2) : e2.call(null), r.clearImmediate(t3));
        }), t3;
      }, r.clearImmediate = "function" == typeof n ? n : function(e2) {
        delete u[e2];
      };
    }).call(this, e("timers").setImmediate, e("timers").clearImmediate);
  }, {"process/browser.js": 8, timers: 16}], 8: [function(e, t, r) {
    function n() {
      throw new Error("setTimeout has not been defined");
    }
    function i() {
      throw new Error("clearTimeout has not been defined");
    }
    function o(e2) {
      if (h === setTimeout)
        return setTimeout(e2, 0);
      if ((h === n || !h) && setTimeout)
        return h = setTimeout, setTimeout(e2, 0);
      try {
        return h(e2, 0);
      } catch (t2) {
        try {
          return h.call(null, e2, 0);
        } catch (t3) {
          return h.call(this, e2, 0);
        }
      }
    }
    function s(e2) {
      if (p === clearTimeout)
        return clearTimeout(e2);
      if ((p === i || !p) && clearTimeout)
        return p = clearTimeout, clearTimeout(e2);
      try {
        return p(e2);
      } catch (t2) {
        try {
          return p.call(null, e2);
        } catch (t3) {
          return p.call(this, e2);
        }
      }
    }
    function a() {
      v && d && (v = false, d.length ? m = d.concat(m) : g = -1, m.length && u());
    }
    function u() {
      if (!v) {
        var e2 = o(a);
        v = true;
        for (var t2 = m.length; t2; ) {
          for (d = m, m = []; ++g < t2; )
            d && d[g].run();
          g = -1, t2 = m.length;
        }
        d = null, v = false, s(e2);
      }
    }
    function c(e2, t2) {
      this.fun = e2, this.array = t2;
    }
    function l() {
    }
    var h, p, f = t.exports = {};
    !function() {
      try {
        h = "function" == typeof setTimeout ? setTimeout : n;
      } catch (e2) {
        h = n;
      }
      try {
        p = "function" == typeof clearTimeout ? clearTimeout : i;
      } catch (e2) {
        p = i;
      }
    }();
    var d, m = [], v = false, g = -1;
    f.nextTick = function(e2) {
      var t2 = new Array(arguments.length - 1);
      if (arguments.length > 1)
        for (var r2 = 1; r2 < arguments.length; r2++)
          t2[r2 - 1] = arguments[r2];
      m.push(new c(e2, t2)), 1 !== m.length || v || o(u);
    }, c.prototype.run = function() {
      this.fun.apply(null, this.array);
    }, f.title = "browser", f.browser = true, f.env = {}, f.argv = [], f.version = "", f.versions = {}, f.on = l, f.addListener = l, f.once = l, f.off = l, f.removeListener = l, f.removeAllListeners = l, f.emit = l, f.prependListener = l, f.prependOnceListener = l, f.listeners = function(e2) {
      return [];
    }, f.binding = function(e2) {
      throw new Error("process.binding is not supported");
    }, f.cwd = function() {
      return "/";
    }, f.chdir = function(e2) {
      throw new Error("process.chdir is not supported");
    }, f.umask = function() {
      return 0;
    };
  }, {}], 7: [function(e, t, r) {
    !function(e2) {
      "use strict";
      function t2(e3) {
        return null !== e3 && "[object Array]" === Object.prototype.toString.call(e3);
      }
      function r2(e3) {
        return null !== e3 && "[object Object]" === Object.prototype.toString.call(e3);
      }
      function n(e3, i2) {
        if (e3 === i2)
          return true;
        if (Object.prototype.toString.call(e3) !== Object.prototype.toString.call(i2))
          return false;
        if (true === t2(e3)) {
          if (e3.length !== i2.length)
            return false;
          for (var o2 = 0; o2 < e3.length; o2++)
            if (false === n(e3[o2], i2[o2]))
              return false;
          return true;
        }
        if (true === r2(e3)) {
          var s2 = {};
          for (var a2 in e3)
            if (hasOwnProperty.call(e3, a2)) {
              if (false === n(e3[a2], i2[a2]))
                return false;
              s2[a2] = true;
            }
          for (var u2 in i2)
            if (hasOwnProperty.call(i2, u2) && true !== s2[u2])
              return false;
          return true;
        }
        return false;
      }
      function i(e3) {
        if ("" === e3 || false === e3 || null === e3)
          return true;
        if (t2(e3) && 0 === e3.length)
          return true;
        if (r2(e3)) {
          for (var n2 in e3)
            if (e3.hasOwnProperty(n2))
              return false;
          return true;
        }
        return false;
      }
      function o(e3) {
        for (var t3 = Object.keys(e3), r3 = [], n2 = 0; n2 < t3.length; n2++)
          r3.push(e3[t3[n2]]);
        return r3;
      }
      function s(e3) {
        return e3 >= "a" && e3 <= "z" || e3 >= "A" && e3 <= "Z" || "_" === e3;
      }
      function a(e3) {
        return e3 >= "0" && e3 <= "9" || "-" === e3;
      }
      function u(e3) {
        return e3 >= "a" && e3 <= "z" || e3 >= "A" && e3 <= "Z" || e3 >= "0" && e3 <= "9" || "_" === e3;
      }
      function c() {
      }
      function l() {
      }
      function h(e3) {
        this.runtime = e3;
      }
      function p(e3) {
        this._interpreter = e3, this.functionTable = {abs: {_func: this._functionAbs, _signature: [{types: [g]}]}, avg: {_func: this._functionAvg, _signature: [{types: [S]}]}, ceil: {_func: this._functionCeil, _signature: [{types: [g]}]}, contains: {_func: this._functionContains, _signature: [{types: [b, w]}, {types: [y]}]}, ends_with: {_func: this._functionEndsWith, _signature: [{types: [b]}, {types: [b]}]}, floor: {_func: this._functionFloor, _signature: [{types: [g]}]}, length: {_func: this._functionLength, _signature: [{types: [b, w, E]}]}, map: {_func: this._functionMap, _signature: [{types: [_]}, {types: [w]}]}, max: {_func: this._functionMax, _signature: [{types: [S, C]}]}, merge: {_func: this._functionMerge, _signature: [{types: [E], variadic: true}]}, max_by: {_func: this._functionMaxBy, _signature: [{types: [w]}, {types: [_]}]}, sum: {_func: this._functionSum, _signature: [{types: [S]}]}, starts_with: {_func: this._functionStartsWith, _signature: [{types: [b]}, {types: [b]}]}, min: {_func: this._functionMin, _signature: [{types: [S, C]}]}, min_by: {_func: this._functionMinBy, _signature: [{types: [w]}, {types: [_]}]}, type: {_func: this._functionType, _signature: [{types: [y]}]}, keys: {_func: this._functionKeys, _signature: [{types: [E]}]}, values: {_func: this._functionValues, _signature: [{types: [E]}]}, sort: {_func: this._functionSort, _signature: [{types: [C, S]}]}, sort_by: {_func: this._functionSortBy, _signature: [{types: [w]}, {types: [_]}]}, join: {_func: this._functionJoin, _signature: [{types: [b]}, {types: [C]}]}, reverse: {_func: this._functionReverse, _signature: [{types: [b, w]}]}, to_array: {_func: this._functionToArray, _signature: [{types: [y]}]}, to_string: {_func: this._functionToString, _signature: [{types: [y]}]}, to_number: {_func: this._functionToNumber, _signature: [{types: [y]}]}, not_null: {_func: this._functionNotNull, _signature: [{types: [y], variadic: true}]}};
      }
      function f(e3) {
        return new l().parse(e3);
      }
      function d(e3) {
        return new c().tokenize(e3);
      }
      function m(e3, t3) {
        var r3 = new l(), n2 = new p(), i2 = new h(n2);
        n2._interpreter = i2;
        var o2 = r3.parse(t3);
        return i2.search(o2, e3);
      }
      var v;
      v = "function" == typeof String.prototype.trimLeft ? function(e3) {
        return e3.trimLeft();
      } : function(e3) {
        return e3.match(/^\s*(.*)/)[1];
      };
      var g = 0, y = 1, b = 2, w = 3, E = 4, _ = 6, S = 8, C = 9, x = {".": "Dot", "*": "Star", ",": "Comma", ":": "Colon", "{": "Lbrace", "}": "Rbrace", "]": "Rbracket", "(": "Lparen", ")": "Rparen", "@": "Current"}, R = {"<": true, ">": true, "=": true, "!": true}, A = {" ": true, "	": true, "\n": true};
      c.prototype = {tokenize: function(e3) {
        var t3 = [];
        this._current = 0;
        for (var r3, n2, i2; this._current < e3.length; )
          if (s(e3[this._current]))
            r3 = this._current, n2 = this._consumeUnquotedIdentifier(e3), t3.push({type: "UnquotedIdentifier", value: n2, start: r3});
          else if (void 0 !== x[e3[this._current]])
            t3.push({type: x[e3[this._current]], value: e3[this._current], start: this._current}), this._current++;
          else if (a(e3[this._current]))
            i2 = this._consumeNumber(e3), t3.push(i2);
          else if ("[" === e3[this._current])
            i2 = this._consumeLBracket(e3), t3.push(i2);
          else if ('"' === e3[this._current])
            r3 = this._current, n2 = this._consumeQuotedIdentifier(e3), t3.push({type: "QuotedIdentifier", value: n2, start: r3});
          else if ("'" === e3[this._current])
            r3 = this._current, n2 = this._consumeRawStringLiteral(e3), t3.push({type: "Literal", value: n2, start: r3});
          else if ("`" === e3[this._current]) {
            r3 = this._current;
            var o2 = this._consumeLiteral(e3);
            t3.push({type: "Literal", value: o2, start: r3});
          } else if (void 0 !== R[e3[this._current]])
            t3.push(this._consumeOperator(e3));
          else if (void 0 !== A[e3[this._current]])
            this._current++;
          else if ("&" === e3[this._current])
            r3 = this._current, this._current++, "&" === e3[this._current] ? (this._current++, t3.push({type: "And", value: "&&", start: r3})) : t3.push({type: "Expref", value: "&", start: r3});
          else {
            if ("|" !== e3[this._current]) {
              var u2 = new Error("Unknown character:" + e3[this._current]);
              throw u2.name = "LexerError", u2;
            }
            r3 = this._current, this._current++, "|" === e3[this._current] ? (this._current++, t3.push({type: "Or", value: "||", start: r3})) : t3.push({type: "Pipe", value: "|", start: r3});
          }
        return t3;
      }, _consumeUnquotedIdentifier: function(e3) {
        var t3 = this._current;
        for (this._current++; this._current < e3.length && u(e3[this._current]); )
          this._current++;
        return e3.slice(t3, this._current);
      }, _consumeQuotedIdentifier: function(e3) {
        var t3 = this._current;
        this._current++;
        for (var r3 = e3.length; '"' !== e3[this._current] && this._current < r3; ) {
          var n2 = this._current;
          "\\" !== e3[n2] || "\\" !== e3[n2 + 1] && '"' !== e3[n2 + 1] ? n2++ : n2 += 2, this._current = n2;
        }
        return this._current++, JSON.parse(e3.slice(t3, this._current));
      }, _consumeRawStringLiteral: function(e3) {
        var t3 = this._current;
        this._current++;
        for (var r3 = e3.length; "'" !== e3[this._current] && this._current < r3; ) {
          var n2 = this._current;
          "\\" !== e3[n2] || "\\" !== e3[n2 + 1] && "'" !== e3[n2 + 1] ? n2++ : n2 += 2, this._current = n2;
        }
        return this._current++, e3.slice(t3 + 1, this._current - 1).replace("\\'", "'");
      }, _consumeNumber: function(e3) {
        var t3 = this._current;
        this._current++;
        for (var r3 = e3.length; a(e3[this._current]) && this._current < r3; )
          this._current++;
        return {type: "Number", value: parseInt(e3.slice(t3, this._current)), start: t3};
      }, _consumeLBracket: function(e3) {
        var t3 = this._current;
        return this._current++, "?" === e3[this._current] ? (this._current++, {type: "Filter", value: "[?", start: t3}) : "]" === e3[this._current] ? (this._current++, {type: "Flatten", value: "[]", start: t3}) : {type: "Lbracket", value: "[", start: t3};
      }, _consumeOperator: function(e3) {
        var t3 = this._current, r3 = e3[t3];
        return this._current++, "!" === r3 ? "=" === e3[this._current] ? (this._current++, {type: "NE", value: "!=", start: t3}) : {type: "Not", value: "!", start: t3} : "<" === r3 ? "=" === e3[this._current] ? (this._current++, {type: "LTE", value: "<=", start: t3}) : {type: "LT", value: "<", start: t3} : ">" === r3 ? "=" === e3[this._current] ? (this._current++, {type: "GTE", value: ">=", start: t3}) : {type: "GT", value: ">", start: t3} : "=" === r3 && "=" === e3[this._current] ? (this._current++, {type: "EQ", value: "==", start: t3}) : void 0;
      }, _consumeLiteral: function(e3) {
        this._current++;
        for (var t3, r3 = this._current, n2 = e3.length; "`" !== e3[this._current] && this._current < n2; ) {
          var i2 = this._current;
          "\\" !== e3[i2] || "\\" !== e3[i2 + 1] && "`" !== e3[i2 + 1] ? i2++ : i2 += 2, this._current = i2;
        }
        var o2 = v(e3.slice(r3, this._current));
        return o2 = o2.replace("\\`", "`"), t3 = this._looksLikeJSON(o2) ? JSON.parse(o2) : JSON.parse('"' + o2 + '"'), this._current++, t3;
      }, _looksLikeJSON: function(e3) {
        var t3 = '[{"', r3 = ["true", "false", "null"], n2 = "-0123456789";
        if ("" === e3)
          return false;
        if (t3.indexOf(e3[0]) >= 0)
          return true;
        if (r3.indexOf(e3) >= 0)
          return true;
        if (!(n2.indexOf(e3[0]) >= 0))
          return false;
        try {
          return JSON.parse(e3), true;
        } catch (e4) {
          return false;
        }
      }};
      var T = {};
      T.EOF = 0, T.UnquotedIdentifier = 0, T.QuotedIdentifier = 0, T.Rbracket = 0, T.Rparen = 0, T.Comma = 0, T.Rbrace = 0, T.Number = 0, T.Current = 0, T.Expref = 0, T.Pipe = 1, T.Or = 2, T.And = 3, T.EQ = 5, T.GT = 5, T.LT = 5, T.GTE = 5, T.LTE = 5, T.NE = 5, T.Flatten = 9, T.Star = 20, T.Filter = 21, T.Dot = 40, T.Not = 45, T.Lbrace = 50, T.Lbracket = 55, T.Lparen = 60, l.prototype = {parse: function(e3) {
        this._loadTokens(e3), this.index = 0;
        var t3 = this.expression(0);
        if ("EOF" !== this._lookahead(0)) {
          var r3 = this._lookaheadToken(0), n2 = new Error("Unexpected token type: " + r3.type + ", value: " + r3.value);
          throw n2.name = "ParserError", n2;
        }
        return t3;
      }, _loadTokens: function(e3) {
        var t3 = new c(), r3 = t3.tokenize(e3);
        r3.push({type: "EOF", value: "", start: e3.length}), this.tokens = r3;
      }, expression: function(e3) {
        var t3 = this._lookaheadToken(0);
        this._advance();
        for (var r3 = this.nud(t3), n2 = this._lookahead(0); e3 < T[n2]; )
          this._advance(), r3 = this.led(n2, r3), n2 = this._lookahead(0);
        return r3;
      }, _lookahead: function(e3) {
        return this.tokens[this.index + e3].type;
      }, _lookaheadToken: function(e3) {
        return this.tokens[this.index + e3];
      }, _advance: function() {
        this.index++;
      }, nud: function(e3) {
        var t3, r3, n2;
        switch (e3.type) {
          case "Literal":
            return {type: "Literal", value: e3.value};
          case "UnquotedIdentifier":
            return {type: "Field", name: e3.value};
          case "QuotedIdentifier":
            var i2 = {type: "Field", name: e3.value};
            if ("Lparen" === this._lookahead(0))
              throw new Error("Quoted identifier not allowed for function names.");
            return i2;
          case "Not":
            return r3 = this.expression(T.Not), {type: "NotExpression", children: [r3]};
          case "Star":
            return t3 = {type: "Identity"}, r3 = null, r3 = "Rbracket" === this._lookahead(0) ? {type: "Identity"} : this._parseProjectionRHS(T.Star), {type: "ValueProjection", children: [t3, r3]};
          case "Filter":
            return this.led(e3.type, {type: "Identity"});
          case "Lbrace":
            return this._parseMultiselectHash();
          case "Flatten":
            return t3 = {type: "Flatten", children: [{type: "Identity"}]}, r3 = this._parseProjectionRHS(T.Flatten), {type: "Projection", children: [t3, r3]};
          case "Lbracket":
            return "Number" === this._lookahead(0) || "Colon" === this._lookahead(0) ? (r3 = this._parseIndexExpression(), this._projectIfSlice({type: "Identity"}, r3)) : "Star" === this._lookahead(0) && "Rbracket" === this._lookahead(1) ? (this._advance(), this._advance(), r3 = this._parseProjectionRHS(T.Star), {type: "Projection", children: [{type: "Identity"}, r3]}) : this._parseMultiselectList();
          case "Current":
            return {type: "Current"};
          case "Expref":
            return n2 = this.expression(T.Expref), {type: "ExpressionReference", children: [n2]};
          case "Lparen":
            for (var o2 = []; "Rparen" !== this._lookahead(0); )
              "Current" === this._lookahead(0) ? (n2 = {type: "Current"}, this._advance()) : n2 = this.expression(0), o2.push(n2);
            return this._match("Rparen"), o2[0];
          default:
            this._errorToken(e3);
        }
      }, led: function(e3, t3) {
        var r3;
        switch (e3) {
          case "Dot":
            var n2 = T.Dot;
            return "Star" !== this._lookahead(0) ? (r3 = this._parseDotRHS(n2), {type: "Subexpression", children: [t3, r3]}) : (this._advance(), r3 = this._parseProjectionRHS(n2), {type: "ValueProjection", children: [t3, r3]});
          case "Pipe":
            return r3 = this.expression(T.Pipe), {type: "Pipe", children: [t3, r3]};
          case "Or":
            return r3 = this.expression(T.Or), {type: "OrExpression", children: [t3, r3]};
          case "And":
            return r3 = this.expression(T.And), {type: "AndExpression", children: [t3, r3]};
          case "Lparen":
            for (var i2, o2 = t3.name, s2 = []; "Rparen" !== this._lookahead(0); )
              "Current" === this._lookahead(0) ? (i2 = {type: "Current"}, this._advance()) : i2 = this.expression(0), "Comma" === this._lookahead(0) && this._match("Comma"), s2.push(i2);
            return this._match("Rparen"), {type: "Function", name: o2, children: s2};
          case "Filter":
            var a2 = this.expression(0);
            return this._match("Rbracket"), r3 = "Flatten" === this._lookahead(0) ? {type: "Identity"} : this._parseProjectionRHS(T.Filter), {type: "FilterProjection", children: [t3, r3, a2]};
          case "Flatten":
            return {type: "Projection", children: [{type: "Flatten", children: [t3]}, this._parseProjectionRHS(T.Flatten)]};
          case "EQ":
          case "NE":
          case "GT":
          case "GTE":
          case "LT":
          case "LTE":
            return this._parseComparator(t3, e3);
          case "Lbracket":
            var u2 = this._lookaheadToken(0);
            return "Number" === u2.type || "Colon" === u2.type ? (r3 = this._parseIndexExpression(), this._projectIfSlice(t3, r3)) : (this._match("Star"), this._match("Rbracket"), r3 = this._parseProjectionRHS(T.Star), {type: "Projection", children: [t3, r3]});
          default:
            this._errorToken(this._lookaheadToken(0));
        }
      }, _match: function(e3) {
        if (this._lookahead(0) !== e3) {
          var t3 = this._lookaheadToken(0), r3 = new Error("Expected " + e3 + ", got: " + t3.type);
          throw r3.name = "ParserError", r3;
        }
        this._advance();
      }, _errorToken: function(e3) {
        var t3 = new Error("Invalid token (" + e3.type + '): "' + e3.value + '"');
        throw t3.name = "ParserError", t3;
      }, _parseIndexExpression: function() {
        if ("Colon" === this._lookahead(0) || "Colon" === this._lookahead(1))
          return this._parseSliceExpression();
        var e3 = {type: "Index", value: this._lookaheadToken(0).value};
        return this._advance(), this._match("Rbracket"), e3;
      }, _projectIfSlice: function(e3, t3) {
        var r3 = {type: "IndexExpression", children: [e3, t3]};
        return "Slice" === t3.type ? {type: "Projection", children: [r3, this._parseProjectionRHS(T.Star)]} : r3;
      }, _parseSliceExpression: function() {
        for (var e3 = [null, null, null], t3 = 0, r3 = this._lookahead(0); "Rbracket" !== r3 && t3 < 3; ) {
          if ("Colon" === r3)
            t3++, this._advance();
          else {
            if ("Number" !== r3) {
              var n2 = this._lookahead(0), i2 = new Error("Syntax error, unexpected token: " + n2.value + "(" + n2.type + ")");
              throw i2.name = "Parsererror", i2;
            }
            e3[t3] = this._lookaheadToken(0).value, this._advance();
          }
          r3 = this._lookahead(0);
        }
        return this._match("Rbracket"), {type: "Slice", children: e3};
      }, _parseComparator: function(e3, t3) {
        return {type: "Comparator", name: t3, children: [e3, this.expression(T[t3])]};
      }, _parseDotRHS: function(e3) {
        var t3 = this._lookahead(0);
        return ["UnquotedIdentifier", "QuotedIdentifier", "Star"].indexOf(t3) >= 0 ? this.expression(e3) : "Lbracket" === t3 ? (this._match("Lbracket"), this._parseMultiselectList()) : "Lbrace" === t3 ? (this._match("Lbrace"), this._parseMultiselectHash()) : void 0;
      }, _parseProjectionRHS: function(e3) {
        var t3;
        if (T[this._lookahead(0)] < 10)
          t3 = {type: "Identity"};
        else if ("Lbracket" === this._lookahead(0))
          t3 = this.expression(e3);
        else if ("Filter" === this._lookahead(0))
          t3 = this.expression(e3);
        else {
          if ("Dot" !== this._lookahead(0)) {
            var r3 = this._lookaheadToken(0), n2 = new Error("Sytanx error, unexpected token: " + r3.value + "(" + r3.type + ")");
            throw n2.name = "ParserError", n2;
          }
          this._match("Dot"), t3 = this._parseDotRHS(e3);
        }
        return t3;
      }, _parseMultiselectList: function() {
        for (var e3 = []; "Rbracket" !== this._lookahead(0); ) {
          var t3 = this.expression(0);
          if (e3.push(t3), "Comma" === this._lookahead(0) && (this._match("Comma"), "Rbracket" === this._lookahead(0)))
            throw new Error("Unexpected token Rbracket");
        }
        return this._match("Rbracket"), {type: "MultiSelectList", children: e3};
      }, _parseMultiselectHash: function() {
        for (var e3, t3, r3, n2, i2 = [], o2 = ["UnquotedIdentifier", "QuotedIdentifier"]; ; ) {
          if (e3 = this._lookaheadToken(0), o2.indexOf(e3.type) < 0)
            throw new Error("Expecting an identifier token, got: " + e3.type);
          if (t3 = e3.value, this._advance(), this._match("Colon"), r3 = this.expression(0), n2 = {type: "KeyValuePair", name: t3, value: r3}, i2.push(n2), "Comma" === this._lookahead(0))
            this._match("Comma");
          else if ("Rbrace" === this._lookahead(0)) {
            this._match("Rbrace");
            break;
          }
        }
        return {type: "MultiSelectHash", children: i2};
      }}, h.prototype = {search: function(e3, t3) {
        return this.visit(e3, t3);
      }, visit: function(e3, s2) {
        var a2, u2, c2, l2, h2, p2, f2, d2, m2;
        switch (e3.type) {
          case "Field":
            return null === s2 ? null : r2(s2) ? (p2 = s2[e3.name], void 0 === p2 ? null : p2) : null;
          case "Subexpression":
            for (c2 = this.visit(e3.children[0], s2), m2 = 1; m2 < e3.children.length; m2++)
              if (null === (c2 = this.visit(e3.children[1], c2)))
                return null;
            return c2;
          case "IndexExpression":
            return f2 = this.visit(e3.children[0], s2), this.visit(e3.children[1], f2);
          case "Index":
            if (!t2(s2))
              return null;
            var v2 = e3.value;
            return v2 < 0 && (v2 = s2.length + v2), c2 = s2[v2], void 0 === c2 && (c2 = null), c2;
          case "Slice":
            if (!t2(s2))
              return null;
            var g2 = e3.children.slice(0), y2 = this.computeSliceParams(s2.length, g2), b2 = y2[0], w2 = y2[1], E2 = y2[2];
            if (c2 = [], E2 > 0)
              for (m2 = b2; m2 < w2; m2 += E2)
                c2.push(s2[m2]);
            else
              for (m2 = b2; m2 > w2; m2 += E2)
                c2.push(s2[m2]);
            return c2;
          case "Projection":
            var _2 = this.visit(e3.children[0], s2);
            if (!t2(_2))
              return null;
            for (d2 = [], m2 = 0; m2 < _2.length; m2++)
              null !== (u2 = this.visit(e3.children[1], _2[m2])) && d2.push(u2);
            return d2;
          case "ValueProjection":
            if (_2 = this.visit(e3.children[0], s2), !r2(_2))
              return null;
            d2 = [];
            var S2 = o(_2);
            for (m2 = 0; m2 < S2.length; m2++)
              null !== (u2 = this.visit(e3.children[1], S2[m2])) && d2.push(u2);
            return d2;
          case "FilterProjection":
            if (_2 = this.visit(e3.children[0], s2), !t2(_2))
              return null;
            var C2 = [], x2 = [];
            for (m2 = 0; m2 < _2.length; m2++)
              a2 = this.visit(e3.children[2], _2[m2]), i(a2) || C2.push(_2[m2]);
            for (var R2 = 0; R2 < C2.length; R2++)
              null !== (u2 = this.visit(e3.children[1], C2[R2])) && x2.push(u2);
            return x2;
          case "Comparator":
            switch (l2 = this.visit(e3.children[0], s2), h2 = this.visit(e3.children[1], s2), e3.name) {
              case "EQ":
                c2 = n(l2, h2);
                break;
              case "NE":
                c2 = !n(l2, h2);
                break;
              case "GT":
                c2 = l2 > h2;
                break;
              case "GTE":
                c2 = l2 >= h2;
                break;
              case "LT":
                c2 = l2 < h2;
                break;
              case "LTE":
                c2 = l2 <= h2;
                break;
              default:
                throw new Error("Unknown comparator: " + e3.name);
            }
            return c2;
          case "Flatten":
            var A2 = this.visit(e3.children[0], s2);
            if (!t2(A2))
              return null;
            var T2 = [];
            for (m2 = 0; m2 < A2.length; m2++)
              u2 = A2[m2], t2(u2) ? T2.push.apply(T2, u2) : T2.push(u2);
            return T2;
          case "Identity":
            return s2;
          case "MultiSelectList":
            if (null === s2)
              return null;
            for (d2 = [], m2 = 0; m2 < e3.children.length; m2++)
              d2.push(this.visit(e3.children[m2], s2));
            return d2;
          case "MultiSelectHash":
            if (null === s2)
              return null;
            d2 = {};
            var k;
            for (m2 = 0; m2 < e3.children.length; m2++)
              k = e3.children[m2], d2[k.name] = this.visit(k.value, s2);
            return d2;
          case "OrExpression":
            return a2 = this.visit(e3.children[0], s2), i(a2) && (a2 = this.visit(e3.children[1], s2)), a2;
          case "AndExpression":
            return l2 = this.visit(e3.children[0], s2), true === i(l2) ? l2 : this.visit(e3.children[1], s2);
          case "NotExpression":
            return l2 = this.visit(e3.children[0], s2), i(l2);
          case "Literal":
            return e3.value;
          case "Pipe":
            return f2 = this.visit(e3.children[0], s2), this.visit(e3.children[1], f2);
          case "Current":
            return s2;
          case "Function":
            var I = [];
            for (m2 = 0; m2 < e3.children.length; m2++)
              I.push(this.visit(e3.children[m2], s2));
            return this.runtime.callFunction(e3.name, I);
          case "ExpressionReference":
            var L = e3.children[0];
            return L.jmespathType = "Expref", L;
          default:
            throw new Error("Unknown node type: " + e3.type);
        }
      }, computeSliceParams: function(e3, t3) {
        var r3 = t3[0], n2 = t3[1], i2 = t3[2], o2 = [null, null, null];
        if (null === i2)
          i2 = 1;
        else if (0 === i2) {
          var s2 = new Error("Invalid slice, step cannot be 0");
          throw s2.name = "RuntimeError", s2;
        }
        var a2 = i2 < 0;
        return r3 = null === r3 ? a2 ? e3 - 1 : 0 : this.capSliceRange(e3, r3, i2), n2 = null === n2 ? a2 ? -1 : e3 : this.capSliceRange(e3, n2, i2), o2[0] = r3, o2[1] = n2, o2[2] = i2, o2;
      }, capSliceRange: function(e3, t3, r3) {
        return t3 < 0 ? (t3 += e3) < 0 && (t3 = r3 < 0 ? -1 : 0) : t3 >= e3 && (t3 = r3 < 0 ? e3 - 1 : e3), t3;
      }}, p.prototype = {callFunction: function(e3, t3) {
        var r3 = this.functionTable[e3];
        if (void 0 === r3)
          throw new Error("Unknown function: " + e3 + "()");
        return this._validateArgs(e3, t3, r3._signature), r3._func.call(this, t3);
      }, _validateArgs: function(e3, t3, r3) {
        var n2;
        if (r3[r3.length - 1].variadic) {
          if (t3.length < r3.length)
            throw n2 = 1 === r3.length ? " argument" : " arguments", new Error("ArgumentError: " + e3 + "() takes at least" + r3.length + n2 + " but received " + t3.length);
        } else if (t3.length !== r3.length)
          throw n2 = 1 === r3.length ? " argument" : " arguments", new Error("ArgumentError: " + e3 + "() takes " + r3.length + n2 + " but received " + t3.length);
        for (var i2, o2, s2, a2 = 0; a2 < r3.length; a2++) {
          s2 = false, i2 = r3[a2].types, o2 = this._getTypeName(t3[a2]);
          for (var u2 = 0; u2 < i2.length; u2++)
            if (this._typeMatches(o2, i2[u2], t3[a2])) {
              s2 = true;
              break;
            }
          if (!s2)
            throw new Error("TypeError: " + e3 + "() expected argument " + (a2 + 1) + " to be type " + i2 + " but received type " + o2 + " instead.");
        }
      }, _typeMatches: function(e3, t3, r3) {
        if (t3 === y)
          return true;
        if (t3 !== C && t3 !== S && t3 !== w)
          return e3 === t3;
        if (t3 === w)
          return e3 === w;
        if (e3 === w) {
          var n2;
          t3 === S ? n2 = g : t3 === C && (n2 = b);
          for (var i2 = 0; i2 < r3.length; i2++)
            if (!this._typeMatches(this._getTypeName(r3[i2]), n2, r3[i2]))
              return false;
          return true;
        }
      }, _getTypeName: function(e3) {
        switch (Object.prototype.toString.call(e3)) {
          case "[object String]":
            return b;
          case "[object Number]":
            return g;
          case "[object Array]":
            return w;
          case "[object Boolean]":
            return 5;
          case "[object Null]":
            return 7;
          case "[object Object]":
            return "Expref" === e3.jmespathType ? _ : E;
        }
      }, _functionStartsWith: function(e3) {
        return 0 === e3[0].lastIndexOf(e3[1]);
      }, _functionEndsWith: function(e3) {
        var t3 = e3[0], r3 = e3[1];
        return -1 !== t3.indexOf(r3, t3.length - r3.length);
      }, _functionReverse: function(e3) {
        if (this._getTypeName(e3[0]) === b) {
          for (var t3 = e3[0], r3 = "", n2 = t3.length - 1; n2 >= 0; n2--)
            r3 += t3[n2];
          return r3;
        }
        var i2 = e3[0].slice(0);
        return i2.reverse(), i2;
      }, _functionAbs: function(e3) {
        return Math.abs(e3[0]);
      }, _functionCeil: function(e3) {
        return Math.ceil(e3[0]);
      }, _functionAvg: function(e3) {
        for (var t3 = 0, r3 = e3[0], n2 = 0; n2 < r3.length; n2++)
          t3 += r3[n2];
        return t3 / r3.length;
      }, _functionContains: function(e3) {
        return e3[0].indexOf(e3[1]) >= 0;
      }, _functionFloor: function(e3) {
        return Math.floor(e3[0]);
      }, _functionLength: function(e3) {
        return r2(e3[0]) ? Object.keys(e3[0]).length : e3[0].length;
      }, _functionMap: function(e3) {
        for (var t3 = [], r3 = this._interpreter, n2 = e3[0], i2 = e3[1], o2 = 0; o2 < i2.length; o2++)
          t3.push(r3.visit(n2, i2[o2]));
        return t3;
      }, _functionMerge: function(e3) {
        for (var t3 = {}, r3 = 0; r3 < e3.length; r3++) {
          var n2 = e3[r3];
          for (var i2 in n2)
            t3[i2] = n2[i2];
        }
        return t3;
      }, _functionMax: function(e3) {
        if (e3[0].length > 0) {
          if (this._getTypeName(e3[0][0]) === g)
            return Math.max.apply(Math, e3[0]);
          for (var t3 = e3[0], r3 = t3[0], n2 = 1; n2 < t3.length; n2++)
            r3.localeCompare(t3[n2]) < 0 && (r3 = t3[n2]);
          return r3;
        }
        return null;
      }, _functionMin: function(e3) {
        if (e3[0].length > 0) {
          if (this._getTypeName(e3[0][0]) === g)
            return Math.min.apply(Math, e3[0]);
          for (var t3 = e3[0], r3 = t3[0], n2 = 1; n2 < t3.length; n2++)
            t3[n2].localeCompare(r3) < 0 && (r3 = t3[n2]);
          return r3;
        }
        return null;
      }, _functionSum: function(e3) {
        for (var t3 = 0, r3 = e3[0], n2 = 0; n2 < r3.length; n2++)
          t3 += r3[n2];
        return t3;
      }, _functionType: function(e3) {
        switch (this._getTypeName(e3[0])) {
          case g:
            return "number";
          case b:
            return "string";
          case w:
            return "array";
          case E:
            return "object";
          case 5:
            return "boolean";
          case _:
            return "expref";
          case 7:
            return "null";
        }
      }, _functionKeys: function(e3) {
        return Object.keys(e3[0]);
      }, _functionValues: function(e3) {
        for (var t3 = e3[0], r3 = Object.keys(t3), n2 = [], i2 = 0; i2 < r3.length; i2++)
          n2.push(t3[r3[i2]]);
        return n2;
      }, _functionJoin: function(e3) {
        var t3 = e3[0];
        return e3[1].join(t3);
      }, _functionToArray: function(e3) {
        return this._getTypeName(e3[0]) === w ? e3[0] : [e3[0]];
      }, _functionToString: function(e3) {
        return this._getTypeName(e3[0]) === b ? e3[0] : JSON.stringify(e3[0]);
      }, _functionToNumber: function(e3) {
        var t3, r3 = this._getTypeName(e3[0]);
        return r3 === g ? e3[0] : r3 !== b || (t3 = +e3[0], isNaN(t3)) ? null : t3;
      }, _functionNotNull: function(e3) {
        for (var t3 = 0; t3 < e3.length; t3++)
          if (7 !== this._getTypeName(e3[t3]))
            return e3[t3];
        return null;
      }, _functionSort: function(e3) {
        var t3 = e3[0].slice(0);
        return t3.sort(), t3;
      }, _functionSortBy: function(e3) {
        var t3 = e3[0].slice(0);
        if (0 === t3.length)
          return t3;
        var r3 = this._interpreter, n2 = e3[1], i2 = this._getTypeName(r3.visit(n2, t3[0]));
        if ([g, b].indexOf(i2) < 0)
          throw new Error("TypeError");
        for (var o2 = this, s2 = [], a2 = 0; a2 < t3.length; a2++)
          s2.push([a2, t3[a2]]);
        s2.sort(function(e4, t4) {
          var s3 = r3.visit(n2, e4[1]), a3 = r3.visit(n2, t4[1]);
          if (o2._getTypeName(s3) !== i2)
            throw new Error("TypeError: expected " + i2 + ", received " + o2._getTypeName(s3));
          if (o2._getTypeName(a3) !== i2)
            throw new Error("TypeError: expected " + i2 + ", received " + o2._getTypeName(a3));
          return s3 > a3 ? 1 : s3 < a3 ? -1 : e4[0] - t4[0];
        });
        for (var u2 = 0; u2 < s2.length; u2++)
          t3[u2] = s2[u2][1];
        return t3;
      }, _functionMaxBy: function(e3) {
        for (var t3, r3, n2 = e3[1], i2 = e3[0], o2 = this.createKeyFunction(n2, [g, b]), s2 = -1 / 0, a2 = 0; a2 < i2.length; a2++)
          (r3 = o2(i2[a2])) > s2 && (s2 = r3, t3 = i2[a2]);
        return t3;
      }, _functionMinBy: function(e3) {
        for (var t3, r3, n2 = e3[1], i2 = e3[0], o2 = this.createKeyFunction(n2, [g, b]), s2 = 1 / 0, a2 = 0; a2 < i2.length; a2++)
          (r3 = o2(i2[a2])) < s2 && (s2 = r3, t3 = i2[a2]);
        return t3;
      }, createKeyFunction: function(e3, t3) {
        var r3 = this, n2 = this._interpreter;
        return function(i2) {
          var o2 = n2.visit(e3, i2);
          if (t3.indexOf(r3._getTypeName(o2)) < 0) {
            var s2 = "TypeError: expected one of " + t3 + ", received " + r3._getTypeName(o2);
            throw new Error(s2);
          }
          return o2;
        };
      }}, e2.tokenize = d, e2.compile = f, e2.search = m, e2.strictDeepEqual = n;
    }(void 0 === r ? this.jmespath = {} : r);
  }, {}], 2: [function(e, t, r) {
  }, {}]}, {}, []), _xamzrequire = function e(t, r, n) {
    function i(s2, a) {
      if (!r[s2]) {
        if (!t[s2]) {
          var u = "function" == typeof _xamzrequire && _xamzrequire;
          if (!a && u)
            return u(s2, true);
          if (o)
            return o(s2, true);
          var c = new Error("Cannot find module '" + s2 + "'");
          throw c.code = "MODULE_NOT_FOUND", c;
        }
        var l = r[s2] = {exports: {}};
        t[s2][0].call(l.exports, function(e2) {
          var r2 = t[s2][1][e2];
          return i(r2 || e2);
        }, l, l.exports, e, t, r, n);
      }
      return r[s2].exports;
    }
    for (var o = "function" == typeof _xamzrequire && _xamzrequire, s = 0; s < n.length; s++)
      i(n[s]);
    return i;
  }({28: [function(e, t, r) {
    e("./browser_loader");
    var n = e("./core");
    "undefined" != typeof window && (window.AWS = n), void 0 !== t && (t.exports = n), "undefined" != typeof self && (self.AWS = n);
  }, {"./browser_loader": 35, "./core": 39}], 35: [function(e, t, r) {
    (function(r2) {
      var n = e("./util");
      n.crypto.lib = e("./browserCryptoLib"), n.Buffer = e("buffer/").Buffer, n.url = e("url/"), n.querystring = e("querystring/"), n.realClock = e("./realclock/browserClock"), n.environment = "js", n.createEventStream = e("./event-stream/buffered-create-event-stream").createEventStream, n.isBrowser = function() {
        return true;
      }, n.isNode = function() {
        return false;
      };
      var i = e("./core");
      if (t.exports = i, e("./credentials"), e("./credentials/credential_provider_chain"), e("./credentials/temporary_credentials"), e("./credentials/chainable_temporary_credentials"), e("./credentials/web_identity_credentials"), e("./credentials/cognito_identity_credentials"), e("./credentials/saml_credentials"), i.XML.Parser = e("./xml/browser_parser"), e("./http/xhr"), void 0 === r2)
        var r2 = {browser: true};
    }).call(this, e("_process"));
  }, {"./browserCryptoLib": 29, "./core": 39, "./credentials": 40, "./credentials/chainable_temporary_credentials": 41, "./credentials/cognito_identity_credentials": 42, "./credentials/credential_provider_chain": 43, "./credentials/saml_credentials": 44, "./credentials/temporary_credentials": 45, "./credentials/web_identity_credentials": 46, "./event-stream/buffered-create-event-stream": 54, "./http/xhr": 62, "./realclock/browserClock": 81, "./util": 118, "./xml/browser_parser": 119, _process: 8, "buffer/": 3, "querystring/": 15, "url/": 17}], 119: [function(e, t, r) {
    function n() {
    }
    function i(e2, t2) {
      for (var r2 = e2.getElementsByTagName(t2), n2 = 0, i2 = r2.length; n2 < i2; n2++)
        if (r2[n2].parentNode === e2)
          return r2[n2];
    }
    function o(e2, t2) {
      switch (t2 || (t2 = {}), t2.type) {
        case "structure":
          return s(e2, t2);
        case "map":
          return a(e2, t2);
        case "list":
          return u(e2, t2);
        case void 0:
        case null:
          return l(e2);
        default:
          return c(e2, t2);
      }
    }
    function s(e2, t2) {
      var r2 = {};
      return null === e2 ? r2 : (h.each(t2.members, function(n2, s2) {
        if (s2.isXmlAttribute) {
          if (Object.prototype.hasOwnProperty.call(e2.attributes, s2.name)) {
            var a2 = e2.attributes[s2.name].value;
            r2[n2] = o({textContent: a2}, s2);
          }
        } else {
          var u2 = s2.flattened ? e2 : i(e2, s2.name);
          u2 ? r2[n2] = o(u2, s2) : s2.flattened || "list" !== s2.type || t2.api.xmlNoDefaultLists || (r2[n2] = s2.defaultValue);
        }
      }), r2);
    }
    function a(e2, t2) {
      for (var r2 = {}, n2 = t2.key.name || "key", s2 = t2.value.name || "value", a2 = t2.flattened ? t2.name : "entry", u2 = e2.firstElementChild; u2; ) {
        if (u2.nodeName === a2) {
          var c2 = i(u2, n2).textContent, l2 = i(u2, s2);
          r2[c2] = o(l2, t2.value);
        }
        u2 = u2.nextElementSibling;
      }
      return r2;
    }
    function u(e2, t2) {
      for (var r2 = [], n2 = t2.flattened ? t2.name : t2.member.name || "member", i2 = e2.firstElementChild; i2; )
        i2.nodeName === n2 && r2.push(o(i2, t2.member)), i2 = i2.nextElementSibling;
      return r2;
    }
    function c(e2, t2) {
      if (e2.getAttribute) {
        var r2 = e2.getAttribute("encoding");
        "base64" === r2 && (t2 = new p.create({type: r2}));
      }
      var n2 = e2.textContent;
      return "" === n2 && (n2 = null), "function" == typeof t2.toType ? t2.toType(n2) : n2;
    }
    function l(e2) {
      if (void 0 === e2 || null === e2)
        return "";
      if (!e2.firstElementChild)
        return null === e2.parentNode.parentNode ? {} : 0 === e2.childNodes.length ? "" : e2.textContent;
      for (var t2 = {type: "structure", members: {}}, r2 = e2.firstElementChild; r2; ) {
        var n2 = r2.nodeName;
        Object.prototype.hasOwnProperty.call(t2.members, n2) ? t2.members[n2].type = "list" : t2.members[n2] = {name: n2}, r2 = r2.nextElementSibling;
      }
      return s(e2, t2);
    }
    var h = e("../util"), p = e("../model/shape");
    n.prototype.parse = function(e2, t2) {
      if ("" === e2.replace(/^\s+/, ""))
        return {};
      var r2, n2;
      try {
        if (window.DOMParser) {
          try {
            r2 = new DOMParser().parseFromString(e2, "text/xml");
          } catch (e3) {
            throw h.error(new Error("Parse error in document"), {originalError: e3, code: "XMLParserError", retryable: true});
          }
          if (null === r2.documentElement)
            throw h.error(new Error("Cannot parse empty document."), {code: "XMLParserError", retryable: true});
          var s2 = r2.getElementsByTagName("parsererror")[0];
          if (s2 && (s2.parentNode === r2 || "body" === s2.parentNode.nodeName || s2.parentNode.parentNode === r2 || "body" === s2.parentNode.parentNode.nodeName)) {
            var a2 = s2.getElementsByTagName("div")[0] || s2;
            throw h.error(new Error(a2.textContent || "Parser error in document"), {code: "XMLParserError", retryable: true});
          }
        } else {
          if (!window.ActiveXObject)
            throw new Error("Cannot load XML parser");
          if (r2 = new window.ActiveXObject("Microsoft.XMLDOM"), r2.async = false, !r2.loadXML(e2))
            throw h.error(new Error("Parse error in document"), {code: "XMLParserError", retryable: true});
        }
      } catch (e3) {
        n2 = e3;
      }
      if (r2 && r2.documentElement && !n2) {
        var u2 = o(r2.documentElement, t2), c2 = i(r2.documentElement, "ResponseMetadata");
        return c2 && (u2.ResponseMetadata = o(c2, {})), u2;
      }
      if (n2)
        throw h.error(n2 || new Error(), {code: "XMLParserError", retryable: true});
      return {};
    }, t.exports = n;
  }, {"../model/shape": 70, "../util": 118}], 81: [function(e, t, r) {
    t.exports = {now: function() {
      return "undefined" != typeof performance && "function" == typeof performance.now ? performance.now() : Date.now();
    }};
  }, {}], 62: [function(e, t, r) {
    var n = e("../core"), i = e("events").EventEmitter;
    e("../http"), n.XHRClient = n.util.inherit({handleRequest: function(e2, t2, r2, o) {
      var s = this, a = e2.endpoint, u = new i(), c = a.protocol + "//" + a.hostname;
      80 !== a.port && 443 !== a.port && (c += ":" + a.port), c += e2.path;
      var l = new XMLHttpRequest(), h = false;
      e2.stream = l, l.addEventListener("readystatechange", function() {
        try {
          if (0 === l.status)
            return;
        } catch (e3) {
          return;
        }
        this.readyState >= this.HEADERS_RECEIVED && !h && (u.statusCode = l.status, u.headers = s.parseHeaders(l.getAllResponseHeaders()), u.emit("headers", u.statusCode, u.headers, l.statusText), h = true), this.readyState === this.DONE && s.finishRequest(l, u);
      }, false), l.upload.addEventListener("progress", function(e3) {
        u.emit("sendProgress", e3);
      }), l.addEventListener("progress", function(e3) {
        u.emit("receiveProgress", e3);
      }, false), l.addEventListener("timeout", function() {
        o(n.util.error(new Error("Timeout"), {code: "TimeoutError"}));
      }, false), l.addEventListener("error", function() {
        o(n.util.error(new Error("Network Failure"), {code: "NetworkingError"}));
      }, false), l.addEventListener("abort", function() {
        o(n.util.error(new Error("Request aborted"), {code: "RequestAbortedError"}));
      }, false), r2(u), l.open(e2.method, c, false !== t2.xhrAsync), n.util.each(e2.headers, function(e3, t3) {
        "Content-Length" !== e3 && "User-Agent" !== e3 && "Host" !== e3 && l.setRequestHeader(e3, t3);
      }), t2.timeout && false !== t2.xhrAsync && (l.timeout = t2.timeout), t2.xhrWithCredentials && (l.withCredentials = true);
      try {
        l.responseType = "arraybuffer";
      } catch (e3) {
      }
      try {
        e2.body ? l.send(e2.body) : l.send();
      } catch (t3) {
        if (!e2.body || "object" != typeof e2.body.buffer)
          throw t3;
        l.send(e2.body.buffer);
      }
      return u;
    }, parseHeaders: function(e2) {
      var t2 = {};
      return n.util.arrayEach(e2.split(/\r?\n/), function(e3) {
        var r2 = e3.split(":", 1)[0], n2 = e3.substring(r2.length + 2);
        r2.length > 0 && (t2[r2.toLowerCase()] = n2);
      }), t2;
    }, finishRequest: function(e2, t2) {
      var r2;
      if ("arraybuffer" === e2.responseType && e2.response) {
        var i2 = e2.response;
        r2 = new n.util.Buffer(i2.byteLength);
        for (var o = new Uint8Array(i2), s = 0; s < r2.length; ++s)
          r2[s] = o[s];
      }
      try {
        r2 || "string" != typeof e2.responseText || (r2 = new n.util.Buffer(e2.responseText));
      } catch (e3) {
      }
      r2 && t2.emit("data", r2), t2.emit("end");
    }}), n.HttpClient.prototype = n.XHRClient.prototype, n.HttpClient.streamsApiVersion = 1;
  }, {"../core": 39, "../http": 61, events: 4}], 54: [function(e, t, r) {
    function n(e2, t2, r2) {
      for (var n2 = i(e2), s = [], a = 0; a < n2.length; a++)
        s.push(o(t2, n2[a], r2));
      return s;
    }
    var i = e("../event-stream/event-message-chunker").eventMessageChunker, o = e("./parse-event").parseEvent;
    t.exports = {createEventStream: n};
  }, {"../event-stream/event-message-chunker": 55, "./parse-event": 57}], 57: [function(e, t, r) {
    function n(e2, t2, r2) {
      var n2 = o(t2), s = n2.headers[":message-type"];
      if (s) {
        if ("error" === s.value)
          throw i(n2);
        if ("event" !== s.value)
          return;
      }
      var a = n2.headers[":event-type"], u = r2.members[a.value];
      if (u) {
        var c = {}, l = u.eventPayloadMemberName;
        if (l) {
          var h = u.members[l];
          "binary" === h.type ? c[l] = n2.body : c[l] = e2.parse(n2.body.toString(), h);
        }
        for (var p = u.eventHeaderMemberNames, f = 0; f < p.length; f++) {
          var d = p[f];
          n2.headers[d] && (c[d] = u.members[d].toType(n2.headers[d].value));
        }
        var m = {};
        return m[a.value] = c, m;
      }
    }
    function i(e2) {
      var t2 = e2.headers[":error-code"], r2 = e2.headers[":error-message"], n2 = new Error(r2.value || r2);
      return n2.code = n2.name = t2.value || t2, n2;
    }
    var o = e("./parse-message").parseMessage;
    t.exports = {parseEvent: n};
  }, {"./parse-message": 58}], 58: [function(e, t, r) {
    function n(e2) {
      for (var t2 = {}, r2 = 0; r2 < e2.length; ) {
        var n2 = e2.readUInt8(r2++), i2 = e2.slice(r2, r2 + n2).toString();
        switch (r2 += n2, e2.readUInt8(r2++)) {
          case 0:
            t2[i2] = {type: a, value: true};
            break;
          case 1:
            t2[i2] = {type: a, value: false};
            break;
          case 2:
            t2[i2] = {type: u, value: e2.readInt8(r2++)};
            break;
          case 3:
            t2[i2] = {type: c, value: e2.readInt16BE(r2)}, r2 += 2;
            break;
          case 4:
            t2[i2] = {type: l, value: e2.readInt32BE(r2)}, r2 += 4;
            break;
          case 5:
            t2[i2] = {type: h, value: new o(e2.slice(r2, r2 + 8))}, r2 += 8;
            break;
          case 6:
            var s2 = e2.readUInt16BE(r2);
            r2 += 2, t2[i2] = {type: p, value: e2.slice(r2, r2 + s2)}, r2 += s2;
            break;
          case 7:
            var v = e2.readUInt16BE(r2);
            r2 += 2, t2[i2] = {type: f, value: e2.slice(r2, r2 + v).toString()}, r2 += v;
            break;
          case 8:
            t2[i2] = {type: d, value: new Date(new o(e2.slice(r2, r2 + 8)).valueOf())}, r2 += 8;
            break;
          case 9:
            var g = e2.slice(r2, r2 + 16).toString("hex");
            r2 += 16, t2[i2] = {type: m, value: g.substr(0, 8) + "-" + g.substr(8, 4) + "-" + g.substr(12, 4) + "-" + g.substr(16, 4) + "-" + g.substr(20)};
            break;
          default:
            throw new Error("Unrecognized header type tag");
        }
      }
      return t2;
    }
    function i(e2) {
      var t2 = s(e2);
      return {headers: n(t2.headers), body: t2.body};
    }
    var o = e("./int64").Int64, s = e("./split-message").splitMessage, a = "boolean", u = "byte", c = "short", l = "integer", h = "long", p = "binary", f = "string", d = "timestamp", m = "uuid";
    t.exports = {parseMessage: i};
  }, {"./int64": 56, "./split-message": 59}], 59: [function(e, t, r) {
    function n(e2) {
      if (i.Buffer.isBuffer(e2) || (e2 = o(e2)), e2.length < c)
        throw new Error("Provided message too short to accommodate event stream message overhead");
      if (e2.length !== e2.readUInt32BE(0))
        throw new Error("Reported message length does not match received message length");
      var t2 = e2.readUInt32BE(a);
      if (t2 !== i.crypto.crc32(e2.slice(0, a)))
        throw new Error("The prelude checksum specified in the message (" + t2 + ") does not match the calculated CRC32 checksum.");
      var r2 = e2.readUInt32BE(e2.length - u);
      if (r2 !== i.crypto.crc32(e2.slice(0, e2.length - u)))
        throw new Error("The message checksum did not match the expected value of " + r2);
      var n2 = a + u, l = n2 + e2.readUInt32BE(s);
      return {headers: e2.slice(n2, l), body: e2.slice(l, e2.length - u)};
    }
    var i = e("../core").util, o = i.buffer.toBuffer, s = 4, a = 2 * s, u = 4, c = a + 2 * u;
    t.exports = {splitMessage: n};
  }, {"../core": 39}], 56: [function(e, t, r) {
    function n(e2) {
      if (8 !== e2.length)
        throw new Error("Int64 buffers must be exactly 8 bytes");
      o.Buffer.isBuffer(e2) || (e2 = s(e2)), this.bytes = e2;
    }
    function i(e2) {
      for (var t2 = 0; t2 < 8; t2++)
        e2[t2] ^= 255;
      for (var t2 = 7; t2 > -1 && 0 === ++e2[t2]; t2--)
        ;
    }
    var o = e("../core").util, s = o.buffer.toBuffer;
    n.fromNumber = function(e2) {
      if (e2 > 9223372036854776e3 || e2 < -9223372036854776e3)
        throw new Error(e2 + " is too large (or, if negative, too small) to represent as an Int64");
      for (var t2 = new Uint8Array(8), r2 = 7, o2 = Math.abs(Math.round(e2)); r2 > -1 && o2 > 0; r2--, o2 /= 256)
        t2[r2] = o2;
      return e2 < 0 && i(t2), new n(t2);
    }, n.prototype.valueOf = function() {
      var e2 = this.bytes.slice(0), t2 = 128 & e2[0];
      return t2 && i(e2), parseInt(e2.toString("hex"), 16) * (t2 ? -1 : 1);
    }, n.prototype.toString = function() {
      return String(this.valueOf());
    }, t.exports = {Int64: n};
  }, {"../core": 39}], 55: [function(e, t, r) {
    function n(e2) {
      for (var t2 = [], r2 = 0; r2 < e2.length; ) {
        var n2 = e2.readInt32BE(r2), i = e2.slice(r2, n2 + r2);
        r2 += n2, t2.push(i);
      }
      return t2;
    }
    t.exports = {eventMessageChunker: n};
  }, {}], 46: [function(e, t, r) {
    var n = e("../core");
    n.WebIdentityCredentials = n.util.inherit(n.Credentials, {constructor: function(e2, t2) {
      n.Credentials.call(this), this.expired = true, this.params = e2, this.params.RoleSessionName = this.params.RoleSessionName || "web-identity", this.data = null, this._clientConfig = n.util.copy(t2 || {});
    }, refresh: function(e2) {
      this.coalesceRefresh(e2 || n.util.fn.callback);
    }, load: function(e2) {
      var t2 = this;
      t2.createClients(), t2.service.assumeRoleWithWebIdentity(function(r2, n2) {
        t2.data = null, r2 || (t2.data = n2, t2.service.credentialsFrom(n2, t2)), e2(r2);
      });
    }, createClients: function() {
      if (!this.service) {
        var e2 = n.util.merge({}, this._clientConfig);
        e2.params = this.params, this.service = new n.STS(e2);
      }
    }});
  }, {"../core": 39}], 45: [function(e, t, r) {
    var n = e("../core");
    n.TemporaryCredentials = n.util.inherit(n.Credentials, {constructor: function(e2, t2) {
      n.Credentials.call(this), this.loadMasterCredentials(t2), this.expired = true, this.params = e2 || {}, this.params.RoleArn && (this.params.RoleSessionName = this.params.RoleSessionName || "temporary-credentials");
    }, refresh: function(e2) {
      this.coalesceRefresh(e2 || n.util.fn.callback);
    }, load: function(e2) {
      var t2 = this;
      t2.createClients(), t2.masterCredentials.get(function() {
        t2.service.config.credentials = t2.masterCredentials, (t2.params.RoleArn ? t2.service.assumeRole : t2.service.getSessionToken).call(t2.service, function(r2, n2) {
          r2 || t2.service.credentialsFrom(n2, t2), e2(r2);
        });
      });
    }, loadMasterCredentials: function(e2) {
      for (this.masterCredentials = e2 || n.config.credentials; this.masterCredentials.masterCredentials; )
        this.masterCredentials = this.masterCredentials.masterCredentials;
      "function" != typeof this.masterCredentials.get && (this.masterCredentials = new n.Credentials(this.masterCredentials));
    }, createClients: function() {
      this.service = this.service || new n.STS({params: this.params});
    }});
  }, {"../core": 39}], 44: [function(e, t, r) {
    var n = e("../core");
    n.SAMLCredentials = n.util.inherit(n.Credentials, {constructor: function(e2) {
      n.Credentials.call(this), this.expired = true, this.params = e2;
    }, refresh: function(e2) {
      this.coalesceRefresh(e2 || n.util.fn.callback);
    }, load: function(e2) {
      var t2 = this;
      t2.createClients(), t2.service.assumeRoleWithSAML(function(r2, n2) {
        r2 || t2.service.credentialsFrom(n2, t2), e2(r2);
      });
    }, createClients: function() {
      this.service = this.service || new n.STS({params: this.params});
    }});
  }, {"../core": 39}], 42: [function(e, t, r) {
    var n = e("../core");
    n.CognitoIdentityCredentials = n.util.inherit(n.Credentials, {localStorageKey: {id: "aws.cognito.identity-id.", providers: "aws.cognito.identity-providers."}, constructor: function(e2, t2) {
      n.Credentials.call(this), this.expired = true, this.params = e2, this.data = null, this._identityId = null, this._clientConfig = n.util.copy(t2 || {}), this.loadCachedId();
      var r2 = this;
      Object.defineProperty(this, "identityId", {get: function() {
        return r2.loadCachedId(), r2._identityId || r2.params.IdentityId;
      }, set: function(e3) {
        r2._identityId = e3;
      }});
    }, refresh: function(e2) {
      this.coalesceRefresh(e2 || n.util.fn.callback);
    }, load: function(e2) {
      var t2 = this;
      t2.createClients(), t2.data = null, t2._identityId = null, t2.getId(function(r2) {
        r2 ? (t2.clearIdOnNotAuthorized(r2), e2(r2)) : t2.params.RoleArn ? t2.getCredentialsFromSTS(e2) : t2.getCredentialsForIdentity(e2);
      });
    }, clearCachedId: function() {
      this._identityId = null, delete this.params.IdentityId;
      var e2 = this.params.IdentityPoolId, t2 = this.params.LoginId || "";
      delete this.storage[this.localStorageKey.id + e2 + t2], delete this.storage[this.localStorageKey.providers + e2 + t2];
    }, clearIdOnNotAuthorized: function(e2) {
      var t2 = this;
      "NotAuthorizedException" == e2.code && t2.clearCachedId();
    }, getId: function(e2) {
      var t2 = this;
      if ("string" == typeof t2.params.IdentityId)
        return e2(null, t2.params.IdentityId);
      t2.cognito.getId(function(r2, n2) {
        !r2 && n2.IdentityId ? (t2.params.IdentityId = n2.IdentityId, e2(null, n2.IdentityId)) : e2(r2);
      });
    }, loadCredentials: function(e2, t2) {
      e2 && t2 && (t2.expired = false, t2.accessKeyId = e2.Credentials.AccessKeyId, t2.secretAccessKey = e2.Credentials.SecretKey, t2.sessionToken = e2.Credentials.SessionToken, t2.expireTime = e2.Credentials.Expiration);
    }, getCredentialsForIdentity: function(e2) {
      var t2 = this;
      t2.cognito.getCredentialsForIdentity(function(r2, n2) {
        r2 ? t2.clearIdOnNotAuthorized(r2) : (t2.cacheId(n2), t2.data = n2, t2.loadCredentials(t2.data, t2)), e2(r2);
      });
    }, getCredentialsFromSTS: function(e2) {
      var t2 = this;
      t2.cognito.getOpenIdToken(function(r2, n2) {
        r2 ? (t2.clearIdOnNotAuthorized(r2), e2(r2)) : (t2.cacheId(n2), t2.params.WebIdentityToken = n2.Token, t2.webIdentityCredentials.refresh(function(r3) {
          r3 || (t2.data = t2.webIdentityCredentials.data, t2.sts.credentialsFrom(t2.data, t2)), e2(r3);
        }));
      });
    }, loadCachedId: function() {
      var e2 = this;
      if (n.util.isBrowser() && !e2.params.IdentityId) {
        var t2 = e2.getStorage("id");
        if (t2 && e2.params.Logins) {
          var r2 = Object.keys(e2.params.Logins);
          0 !== (e2.getStorage("providers") || "").split(",").filter(function(e3) {
            return -1 !== r2.indexOf(e3);
          }).length && (e2.params.IdentityId = t2);
        } else
          t2 && (e2.params.IdentityId = t2);
      }
    }, createClients: function() {
      var e2 = this._clientConfig;
      if (this.webIdentityCredentials = this.webIdentityCredentials || new n.WebIdentityCredentials(this.params, e2), !this.cognito) {
        var t2 = n.util.merge({}, e2);
        t2.params = this.params, this.cognito = new n.CognitoIdentity(t2);
      }
      this.sts = this.sts || new n.STS(e2);
    }, cacheId: function(e2) {
      this._identityId = e2.IdentityId, this.params.IdentityId = this._identityId, n.util.isBrowser() && (this.setStorage("id", e2.IdentityId), this.params.Logins && this.setStorage("providers", Object.keys(this.params.Logins).join(",")));
    }, getStorage: function(e2) {
      return this.storage[this.localStorageKey[e2] + this.params.IdentityPoolId + (this.params.LoginId || "")];
    }, setStorage: function(e2, t2) {
      try {
        this.storage[this.localStorageKey[e2] + this.params.IdentityPoolId + (this.params.LoginId || "")] = t2;
      } catch (e3) {
      }
    }, storage: function() {
      try {
        var e2 = n.util.isBrowser() && null !== window.localStorage && "object" == typeof window.localStorage ? window.localStorage : {};
        return e2["aws.test-storage"] = "foobar", delete e2["aws.test-storage"], e2;
      } catch (e3) {
        return {};
      }
    }()});
  }, {"../core": 39}], 41: [function(e, t, r) {
    var n = e("../core");
    n.ChainableTemporaryCredentials = n.util.inherit(n.Credentials, {constructor: function(e2) {
      n.Credentials.call(this), e2 = e2 || {}, this.errorCode = "ChainableTemporaryCredentialsProviderFailure", this.expired = true, this.tokenCodeFn = null;
      var t2 = n.util.copy(e2.params) || {};
      if (t2.RoleArn && (t2.RoleSessionName = t2.RoleSessionName || "temporary-credentials"), t2.SerialNumber) {
        if (!e2.tokenCodeFn || "function" != typeof e2.tokenCodeFn)
          throw new n.util.error(new Error("tokenCodeFn must be a function when params.SerialNumber is given"), {code: this.errorCode});
        this.tokenCodeFn = e2.tokenCodeFn;
      }
      var r2 = n.util.merge({params: t2, credentials: e2.masterCredentials || n.config.credentials}, e2.stsConfig || {});
      this.service = new n.STS(r2);
    }, refresh: function(e2) {
      this.coalesceRefresh(e2 || n.util.fn.callback);
    }, load: function(e2) {
      var t2 = this, r2 = t2.service.config.params.RoleArn ? "assumeRole" : "getSessionToken";
      this.getTokenCode(function(n2, i) {
        var o = {};
        if (n2)
          return void e2(n2);
        i && (o.TokenCode = i), t2.service[r2](o, function(r3, n3) {
          r3 || t2.service.credentialsFrom(n3, t2), e2(r3);
        });
      });
    }, getTokenCode: function(e2) {
      var t2 = this;
      this.tokenCodeFn ? this.tokenCodeFn(this.service.config.params.SerialNumber, function(r2, i) {
        if (r2) {
          var o = r2;
          return r2 instanceof Error && (o = r2.message), void e2(n.util.error(new Error("Error fetching MFA token: " + o), {code: t2.errorCode}));
        }
        e2(null, i);
      }) : e2(null);
    }});
  }, {"../core": 39}], 29: [function(e, t, r) {
    var n = e("./browserHmac"), i = e("./browserMd5"), o = e("./browserSha1"), s = e("./browserSha256");
    t.exports = {createHash: function(e2) {
      if ("md5" === (e2 = e2.toLowerCase()))
        return new i();
      if ("sha256" === e2)
        return new s();
      if ("sha1" === e2)
        return new o();
      throw new Error("Hash algorithm " + e2 + " is not supported in the browser SDK");
    }, createHmac: function(e2, t2) {
      if ("md5" === (e2 = e2.toLowerCase()))
        return new n(i, t2);
      if ("sha256" === e2)
        return new n(s, t2);
      if ("sha1" === e2)
        return new n(o, t2);
      throw new Error("HMAC algorithm " + e2 + " is not supported in the browser SDK");
    }, createSign: function() {
      throw new Error("createSign is not implemented in the browser");
    }};
  }, {"./browserHmac": 31, "./browserMd5": 32, "./browserSha1": 33, "./browserSha256": 34}], 34: [function(e, t, r) {
    function n() {
      this.state = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225], this.temp = new Int32Array(64), this.buffer = new Uint8Array(64), this.bufferLength = 0, this.bytesHashed = 0, this.finished = false;
    }
    var i = e("buffer/").Buffer, o = e("./browserHashUtils"), s = new Uint32Array([1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298]), a = Math.pow(2, 53) - 1;
    t.exports = n, n.BLOCK_SIZE = 64, n.prototype.update = function(e2) {
      if (this.finished)
        throw new Error("Attempted to update an already finished hash.");
      if (o.isEmptyData(e2))
        return this;
      e2 = o.convertToBuffer(e2);
      var t2 = 0, r2 = e2.byteLength;
      if (this.bytesHashed += r2, 8 * this.bytesHashed > a)
        throw new Error("Cannot hash more than 2^53 - 1 bits");
      for (; r2 > 0; )
        this.buffer[this.bufferLength++] = e2[t2++], r2--, 64 === this.bufferLength && (this.hashBuffer(), this.bufferLength = 0);
      return this;
    }, n.prototype.digest = function(e2) {
      if (!this.finished) {
        var t2 = 8 * this.bytesHashed, r2 = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength), n2 = this.bufferLength;
        if (r2.setUint8(this.bufferLength++, 128), n2 % 64 >= 56) {
          for (var o2 = this.bufferLength; o2 < 64; o2++)
            r2.setUint8(o2, 0);
          this.hashBuffer(), this.bufferLength = 0;
        }
        for (var o2 = this.bufferLength; o2 < 56; o2++)
          r2.setUint8(o2, 0);
        r2.setUint32(56, Math.floor(t2 / 4294967296), true), r2.setUint32(60, t2), this.hashBuffer(), this.finished = true;
      }
      for (var s2 = new i(32), o2 = 0; o2 < 8; o2++)
        s2[4 * o2] = this.state[o2] >>> 24 & 255, s2[4 * o2 + 1] = this.state[o2] >>> 16 & 255, s2[4 * o2 + 2] = this.state[o2] >>> 8 & 255, s2[4 * o2 + 3] = this.state[o2] >>> 0 & 255;
      return e2 ? s2.toString(e2) : s2;
    }, n.prototype.hashBuffer = function() {
      for (var e2 = this, t2 = e2.buffer, r2 = e2.state, n2 = r2[0], i2 = r2[1], o2 = r2[2], a2 = r2[3], u = r2[4], c = r2[5], l = r2[6], h = r2[7], p = 0; p < 64; p++) {
        if (p < 16)
          this.temp[p] = (255 & t2[4 * p]) << 24 | (255 & t2[4 * p + 1]) << 16 | (255 & t2[4 * p + 2]) << 8 | 255 & t2[4 * p + 3];
        else {
          var f = this.temp[p - 2], d = (f >>> 17 | f << 15) ^ (f >>> 19 | f << 13) ^ f >>> 10;
          f = this.temp[p - 15];
          var m = (f >>> 7 | f << 25) ^ (f >>> 18 | f << 14) ^ f >>> 3;
          this.temp[p] = (d + this.temp[p - 7] | 0) + (m + this.temp[p - 16] | 0);
        }
        var v = (((u >>> 6 | u << 26) ^ (u >>> 11 | u << 21) ^ (u >>> 25 | u << 7)) + (u & c ^ ~u & l) | 0) + (h + (s[p] + this.temp[p] | 0) | 0) | 0, g = ((n2 >>> 2 | n2 << 30) ^ (n2 >>> 13 | n2 << 19) ^ (n2 >>> 22 | n2 << 10)) + (n2 & i2 ^ n2 & o2 ^ i2 & o2) | 0;
        h = l, l = c, c = u, u = a2 + v | 0, a2 = o2, o2 = i2, i2 = n2, n2 = v + g | 0;
      }
      r2[0] += n2, r2[1] += i2, r2[2] += o2, r2[3] += a2, r2[4] += u, r2[5] += c, r2[6] += l, r2[7] += h;
    };
  }, {"./browserHashUtils": 30, "buffer/": 3}], 33: [function(e, t, r) {
    function n() {
      this.h0 = 1732584193, this.h1 = 4023233417, this.h2 = 2562383102, this.h3 = 271733878, this.h4 = 3285377520, this.block = new Uint32Array(80), this.offset = 0, this.shift = 24, this.totalLength = 0;
    }
    var i = e("buffer/").Buffer, o = e("./browserHashUtils");
    new Uint32Array([1518500249, 1859775393, -1894007588, -899497514]), Math.pow(2, 53), t.exports = n, n.BLOCK_SIZE = 64, n.prototype.update = function(e2) {
      if (this.finished)
        throw new Error("Attempted to update an already finished hash.");
      if (o.isEmptyData(e2))
        return this;
      e2 = o.convertToBuffer(e2);
      var t2 = e2.length;
      this.totalLength += 8 * t2;
      for (var r2 = 0; r2 < t2; r2++)
        this.write(e2[r2]);
      return this;
    }, n.prototype.write = function(e2) {
      this.block[this.offset] |= (255 & e2) << this.shift, this.shift ? this.shift -= 8 : (this.offset++, this.shift = 24), 16 === this.offset && this.processBlock();
    }, n.prototype.digest = function(e2) {
      this.write(128), (this.offset > 14 || 14 === this.offset && this.shift < 24) && this.processBlock(), this.offset = 14, this.shift = 24, this.write(0), this.write(0), this.write(this.totalLength > 1099511627775 ? this.totalLength / 1099511627776 : 0), this.write(this.totalLength > 4294967295 ? this.totalLength / 4294967296 : 0);
      for (var t2 = 24; t2 >= 0; t2 -= 8)
        this.write(this.totalLength >> t2);
      var r2 = new i(20), n2 = new DataView(r2.buffer);
      return n2.setUint32(0, this.h0, false), n2.setUint32(4, this.h1, false), n2.setUint32(8, this.h2, false), n2.setUint32(12, this.h3, false), n2.setUint32(16, this.h4, false), e2 ? r2.toString(e2) : r2;
    }, n.prototype.processBlock = function() {
      for (var e2 = 16; e2 < 80; e2++) {
        var t2 = this.block[e2 - 3] ^ this.block[e2 - 8] ^ this.block[e2 - 14] ^ this.block[e2 - 16];
        this.block[e2] = t2 << 1 | t2 >>> 31;
      }
      var r2, n2, i2 = this.h0, o2 = this.h1, s = this.h2, a = this.h3, u = this.h4;
      for (e2 = 0; e2 < 80; e2++) {
        e2 < 20 ? (r2 = a ^ o2 & (s ^ a), n2 = 1518500249) : e2 < 40 ? (r2 = o2 ^ s ^ a, n2 = 1859775393) : e2 < 60 ? (r2 = o2 & s | a & (o2 | s), n2 = 2400959708) : (r2 = o2 ^ s ^ a, n2 = 3395469782);
        var c = (i2 << 5 | i2 >>> 27) + r2 + u + n2 + (0 | this.block[e2]);
        u = a, a = s, s = o2 << 30 | o2 >>> 2, o2 = i2, i2 = c;
      }
      for (this.h0 = this.h0 + i2 | 0, this.h1 = this.h1 + o2 | 0, this.h2 = this.h2 + s | 0, this.h3 = this.h3 + a | 0, this.h4 = this.h4 + u | 0, this.offset = 0, e2 = 0; e2 < 16; e2++)
        this.block[e2] = 0;
    };
  }, {"./browserHashUtils": 30, "buffer/": 3}], 32: [function(e, t, r) {
    function n() {
      this.state = [1732584193, 4023233417, 2562383102, 271733878], this.buffer = new DataView(new ArrayBuffer(h)), this.bufferLength = 0, this.bytesHashed = 0, this.finished = false;
    }
    function i(e2, t2, r2, n2, i2, o2) {
      return ((t2 = (t2 + e2 & 4294967295) + (n2 + o2 & 4294967295) & 4294967295) << i2 | t2 >>> 32 - i2) + r2 & 4294967295;
    }
    function o(e2, t2, r2, n2, o2, s2, a2) {
      return i(t2 & r2 | ~t2 & n2, e2, t2, o2, s2, a2);
    }
    function s(e2, t2, r2, n2, o2, s2, a2) {
      return i(t2 & n2 | r2 & ~n2, e2, t2, o2, s2, a2);
    }
    function a(e2, t2, r2, n2, o2, s2, a2) {
      return i(t2 ^ r2 ^ n2, e2, t2, o2, s2, a2);
    }
    function u(e2, t2, r2, n2, o2, s2, a2) {
      return i(r2 ^ (t2 | ~n2), e2, t2, o2, s2, a2);
    }
    var c = e("./browserHashUtils"), l = e("buffer/").Buffer, h = 64;
    t.exports = n, n.BLOCK_SIZE = h, n.prototype.update = function(e2) {
      if (c.isEmptyData(e2))
        return this;
      if (this.finished)
        throw new Error("Attempted to update an already finished hash.");
      var t2 = c.convertToBuffer(e2), r2 = 0, n2 = t2.byteLength;
      for (this.bytesHashed += n2; n2 > 0; )
        this.buffer.setUint8(this.bufferLength++, t2[r2++]), n2--, this.bufferLength === h && (this.hashBuffer(), this.bufferLength = 0);
      return this;
    }, n.prototype.digest = function(e2) {
      if (!this.finished) {
        var t2 = this, r2 = t2.buffer, n2 = t2.bufferLength, i2 = t2.bytesHashed, o2 = 8 * i2;
        if (r2.setUint8(this.bufferLength++, 128), n2 % h >= h - 8) {
          for (var s2 = this.bufferLength; s2 < h; s2++)
            r2.setUint8(s2, 0);
          this.hashBuffer(), this.bufferLength = 0;
        }
        for (var s2 = this.bufferLength; s2 < h - 8; s2++)
          r2.setUint8(s2, 0);
        r2.setUint32(h - 8, o2 >>> 0, true), r2.setUint32(h - 4, Math.floor(o2 / 4294967296), true), this.hashBuffer(), this.finished = true;
      }
      for (var a2 = new DataView(new ArrayBuffer(16)), s2 = 0; s2 < 4; s2++)
        a2.setUint32(4 * s2, this.state[s2], true);
      var u2 = new l(a2.buffer, a2.byteOffset, a2.byteLength);
      return e2 ? u2.toString(e2) : u2;
    }, n.prototype.hashBuffer = function() {
      var e2 = this, t2 = e2.buffer, r2 = e2.state, n2 = r2[0], i2 = r2[1], c2 = r2[2], l2 = r2[3];
      n2 = o(n2, i2, c2, l2, t2.getUint32(0, true), 7, 3614090360), l2 = o(l2, n2, i2, c2, t2.getUint32(4, true), 12, 3905402710), c2 = o(c2, l2, n2, i2, t2.getUint32(8, true), 17, 606105819), i2 = o(i2, c2, l2, n2, t2.getUint32(12, true), 22, 3250441966), n2 = o(n2, i2, c2, l2, t2.getUint32(16, true), 7, 4118548399), l2 = o(l2, n2, i2, c2, t2.getUint32(20, true), 12, 1200080426), c2 = o(c2, l2, n2, i2, t2.getUint32(24, true), 17, 2821735955), i2 = o(i2, c2, l2, n2, t2.getUint32(28, true), 22, 4249261313), n2 = o(n2, i2, c2, l2, t2.getUint32(32, true), 7, 1770035416), l2 = o(l2, n2, i2, c2, t2.getUint32(36, true), 12, 2336552879), c2 = o(c2, l2, n2, i2, t2.getUint32(40, true), 17, 4294925233), i2 = o(i2, c2, l2, n2, t2.getUint32(44, true), 22, 2304563134), n2 = o(n2, i2, c2, l2, t2.getUint32(48, true), 7, 1804603682), l2 = o(l2, n2, i2, c2, t2.getUint32(52, true), 12, 4254626195), c2 = o(c2, l2, n2, i2, t2.getUint32(56, true), 17, 2792965006), i2 = o(i2, c2, l2, n2, t2.getUint32(60, true), 22, 1236535329), n2 = s(n2, i2, c2, l2, t2.getUint32(4, true), 5, 4129170786), l2 = s(l2, n2, i2, c2, t2.getUint32(24, true), 9, 3225465664), c2 = s(c2, l2, n2, i2, t2.getUint32(44, true), 14, 643717713), i2 = s(i2, c2, l2, n2, t2.getUint32(0, true), 20, 3921069994), n2 = s(n2, i2, c2, l2, t2.getUint32(20, true), 5, 3593408605), l2 = s(l2, n2, i2, c2, t2.getUint32(40, true), 9, 38016083), c2 = s(c2, l2, n2, i2, t2.getUint32(60, true), 14, 3634488961), i2 = s(i2, c2, l2, n2, t2.getUint32(16, true), 20, 3889429448), n2 = s(n2, i2, c2, l2, t2.getUint32(36, true), 5, 568446438), l2 = s(l2, n2, i2, c2, t2.getUint32(56, true), 9, 3275163606), c2 = s(c2, l2, n2, i2, t2.getUint32(12, true), 14, 4107603335), i2 = s(i2, c2, l2, n2, t2.getUint32(32, true), 20, 1163531501), n2 = s(n2, i2, c2, l2, t2.getUint32(52, true), 5, 2850285829), l2 = s(l2, n2, i2, c2, t2.getUint32(8, true), 9, 4243563512), c2 = s(c2, l2, n2, i2, t2.getUint32(28, true), 14, 1735328473), i2 = s(i2, c2, l2, n2, t2.getUint32(48, true), 20, 2368359562), n2 = a(n2, i2, c2, l2, t2.getUint32(20, true), 4, 4294588738), l2 = a(l2, n2, i2, c2, t2.getUint32(32, true), 11, 2272392833), c2 = a(c2, l2, n2, i2, t2.getUint32(44, true), 16, 1839030562), i2 = a(i2, c2, l2, n2, t2.getUint32(56, true), 23, 4259657740), n2 = a(n2, i2, c2, l2, t2.getUint32(4, true), 4, 2763975236), l2 = a(l2, n2, i2, c2, t2.getUint32(16, true), 11, 1272893353), c2 = a(c2, l2, n2, i2, t2.getUint32(28, true), 16, 4139469664), i2 = a(i2, c2, l2, n2, t2.getUint32(40, true), 23, 3200236656), n2 = a(n2, i2, c2, l2, t2.getUint32(52, true), 4, 681279174), l2 = a(l2, n2, i2, c2, t2.getUint32(0, true), 11, 3936430074), c2 = a(c2, l2, n2, i2, t2.getUint32(12, true), 16, 3572445317), i2 = a(i2, c2, l2, n2, t2.getUint32(24, true), 23, 76029189), n2 = a(n2, i2, c2, l2, t2.getUint32(36, true), 4, 3654602809), l2 = a(l2, n2, i2, c2, t2.getUint32(48, true), 11, 3873151461), c2 = a(c2, l2, n2, i2, t2.getUint32(60, true), 16, 530742520), i2 = a(i2, c2, l2, n2, t2.getUint32(8, true), 23, 3299628645), n2 = u(n2, i2, c2, l2, t2.getUint32(0, true), 6, 4096336452), l2 = u(l2, n2, i2, c2, t2.getUint32(28, true), 10, 1126891415), c2 = u(c2, l2, n2, i2, t2.getUint32(56, true), 15, 2878612391), i2 = u(i2, c2, l2, n2, t2.getUint32(20, true), 21, 4237533241), n2 = u(n2, i2, c2, l2, t2.getUint32(48, true), 6, 1700485571), l2 = u(l2, n2, i2, c2, t2.getUint32(12, true), 10, 2399980690), c2 = u(c2, l2, n2, i2, t2.getUint32(40, true), 15, 4293915773), i2 = u(i2, c2, l2, n2, t2.getUint32(4, true), 21, 2240044497), n2 = u(n2, i2, c2, l2, t2.getUint32(32, true), 6, 1873313359), l2 = u(l2, n2, i2, c2, t2.getUint32(60, true), 10, 4264355552), c2 = u(c2, l2, n2, i2, t2.getUint32(24, true), 15, 2734768916), i2 = u(i2, c2, l2, n2, t2.getUint32(52, true), 21, 1309151649), n2 = u(n2, i2, c2, l2, t2.getUint32(16, true), 6, 4149444226), l2 = u(l2, n2, i2, c2, t2.getUint32(44, true), 10, 3174756917), c2 = u(c2, l2, n2, i2, t2.getUint32(8, true), 15, 718787259), i2 = u(i2, c2, l2, n2, t2.getUint32(36, true), 21, 3951481745), r2[0] = n2 + r2[0] & 4294967295, r2[1] = i2 + r2[1] & 4294967295, r2[2] = c2 + r2[2] & 4294967295, r2[3] = l2 + r2[3] & 4294967295;
    };
  }, {"./browserHashUtils": 30, "buffer/": 3}], 31: [function(e, t, r) {
    function n(e2, t2) {
      this.hash = new e2(), this.outer = new e2();
      var r2 = i(e2, t2), n2 = new Uint8Array(e2.BLOCK_SIZE);
      n2.set(r2);
      for (var o2 = 0; o2 < e2.BLOCK_SIZE; o2++)
        r2[o2] ^= 54, n2[o2] ^= 92;
      this.hash.update(r2), this.outer.update(n2);
      for (var o2 = 0; o2 < r2.byteLength; o2++)
        r2[o2] = 0;
    }
    function i(e2, t2) {
      var r2 = o.convertToBuffer(t2);
      if (r2.byteLength > e2.BLOCK_SIZE) {
        var n2 = new e2();
        n2.update(r2), r2 = n2.digest();
      }
      var i2 = new Uint8Array(e2.BLOCK_SIZE);
      return i2.set(r2), i2;
    }
    var o = e("./browserHashUtils");
    t.exports = n, n.prototype.update = function(e2) {
      if (o.isEmptyData(e2) || this.error)
        return this;
      try {
        this.hash.update(o.convertToBuffer(e2));
      } catch (e3) {
        this.error = e3;
      }
      return this;
    }, n.prototype.digest = function(e2) {
      return this.outer.finished || this.outer.update(this.hash.digest()), this.outer.digest(e2);
    };
  }, {"./browserHashUtils": 30}], 30: [function(e, t, r) {
    function n(e2) {
      return "string" == typeof e2 ? 0 === e2.length : 0 === e2.byteLength;
    }
    function i(e2) {
      return "string" == typeof e2 && (e2 = new o(e2, "utf8")), ArrayBuffer.isView(e2) ? new Uint8Array(e2.buffer, e2.byteOffset, e2.byteLength / Uint8Array.BYTES_PER_ELEMENT) : new Uint8Array(e2);
    }
    var o = e("buffer/").Buffer;
    "undefined" != typeof ArrayBuffer && void 0 === ArrayBuffer.isView && (ArrayBuffer.isView = function(e2) {
      return s.indexOf(Object.prototype.toString.call(e2)) > -1;
    });
    var s = ["[object Int8Array]", "[object Uint8Array]", "[object Uint8ClampedArray]", "[object Int16Array]", "[object Uint16Array]", "[object Int32Array]", "[object Uint32Array]", "[object Float32Array]", "[object Float64Array]", "[object DataView]"];
    t.exports = {isEmptyData: n, convertToBuffer: i};
  }, {"buffer/": 3}], 17: [function(e, t, r) {
    function n() {
      this.protocol = null, this.slashes = null, this.auth = null, this.host = null, this.port = null, this.hostname = null, this.hash = null, this.search = null, this.query = null, this.pathname = null, this.path = null, this.href = null;
    }
    function i(e2, t2, r2) {
      if (e2 && c(e2) && e2 instanceof n)
        return e2;
      var i2 = new n();
      return i2.parse(e2, t2, r2), i2;
    }
    function o(e2) {
      return u(e2) && (e2 = i(e2)), e2 instanceof n ? e2.format() : n.prototype.format.call(e2);
    }
    function s(e2, t2) {
      return i(e2, false, true).resolve(t2);
    }
    function a(e2, t2) {
      return e2 ? i(e2, false, true).resolveObject(t2) : t2;
    }
    function u(e2) {
      return "string" == typeof e2;
    }
    function c(e2) {
      return "object" == typeof e2 && null !== e2;
    }
    function l(e2) {
      return null === e2;
    }
    function h(e2) {
      return null == e2;
    }
    var p = e("punycode");
    r.parse = i, r.resolve = s, r.resolveObject = a, r.format = o, r.Url = n;
    var f = /^([a-z0-9.+-]+:)/i, d = /:[0-9]*$/, m = ["<", ">", '"', "`", " ", "\r", "\n", "	"], v = ["{", "}", "|", "\\", "^", "`"].concat(m), g = ["'"].concat(v), y = ["%", "/", "?", ";", "#"].concat(g), b = ["/", "?", "#"], w = /^[a-z0-9A-Z_-]{0,63}$/, E = /^([a-z0-9A-Z_-]{0,63})(.*)$/, _ = {javascript: true, "javascript:": true}, S = {javascript: true, "javascript:": true}, C = {http: true, https: true, ftp: true, gopher: true, file: true, "http:": true, "https:": true, "ftp:": true, "gopher:": true, "file:": true}, x = e("querystring");
    n.prototype.parse = function(e2, t2, r2) {
      if (!u(e2))
        throw new TypeError("Parameter 'url' must be a string, not " + typeof e2);
      var n2 = e2;
      n2 = n2.trim();
      var i2 = f.exec(n2);
      if (i2) {
        i2 = i2[0];
        var o2 = i2.toLowerCase();
        this.protocol = o2, n2 = n2.substr(i2.length);
      }
      if (r2 || i2 || n2.match(/^\/\/[^@\/]+@[^@\/]+/)) {
        var s2 = "//" === n2.substr(0, 2);
        !s2 || i2 && S[i2] || (n2 = n2.substr(2), this.slashes = true);
      }
      if (!S[i2] && (s2 || i2 && !C[i2])) {
        for (var a2 = -1, c2 = 0; c2 < b.length; c2++) {
          var l2 = n2.indexOf(b[c2]);
          -1 !== l2 && (-1 === a2 || l2 < a2) && (a2 = l2);
        }
        var h2, d2;
        d2 = -1 === a2 ? n2.lastIndexOf("@") : n2.lastIndexOf("@", a2), -1 !== d2 && (h2 = n2.slice(0, d2), n2 = n2.slice(d2 + 1), this.auth = decodeURIComponent(h2)), a2 = -1;
        for (var c2 = 0; c2 < y.length; c2++) {
          var l2 = n2.indexOf(y[c2]);
          -1 !== l2 && (-1 === a2 || l2 < a2) && (a2 = l2);
        }
        -1 === a2 && (a2 = n2.length), this.host = n2.slice(0, a2), n2 = n2.slice(a2), this.parseHost(), this.hostname = this.hostname || "";
        var m2 = "[" === this.hostname[0] && "]" === this.hostname[this.hostname.length - 1];
        if (!m2)
          for (var v2 = this.hostname.split(/\./), c2 = 0, R = v2.length; c2 < R; c2++) {
            var A = v2[c2];
            if (A && !A.match(w)) {
              for (var T = "", k = 0, I = A.length; k < I; k++)
                A.charCodeAt(k) > 127 ? T += "x" : T += A[k];
              if (!T.match(w)) {
                var L = v2.slice(0, c2), P = v2.slice(c2 + 1), q = A.match(E);
                q && (L.push(q[1]), P.unshift(q[2])), P.length && (n2 = "/" + P.join(".") + n2), this.hostname = L.join(".");
                break;
              }
            }
          }
        if (this.hostname.length > 255 ? this.hostname = "" : this.hostname = this.hostname.toLowerCase(), !m2) {
          for (var O = this.hostname.split("."), N = [], c2 = 0; c2 < O.length; ++c2) {
            var U = O[c2];
            N.push(U.match(/[^A-Za-z0-9_-]/) ? "xn--" + p.encode(U) : U);
          }
          this.hostname = N.join(".");
        }
        var D = this.port ? ":" + this.port : "", M = this.hostname || "";
        this.host = M + D, this.href += this.host, m2 && (this.hostname = this.hostname.substr(1, this.hostname.length - 2), "/" !== n2[0] && (n2 = "/" + n2));
      }
      if (!_[o2])
        for (var c2 = 0, R = g.length; c2 < R; c2++) {
          var j = g[c2], B = encodeURIComponent(j);
          B === j && (B = escape(j)), n2 = n2.split(j).join(B);
        }
      var F = n2.indexOf("#");
      -1 !== F && (this.hash = n2.substr(F), n2 = n2.slice(0, F));
      var H = n2.indexOf("?");
      if (-1 !== H ? (this.search = n2.substr(H), this.query = n2.substr(H + 1), t2 && (this.query = x.parse(this.query)), n2 = n2.slice(0, H)) : t2 && (this.search = "", this.query = {}), n2 && (this.pathname = n2), C[o2] && this.hostname && !this.pathname && (this.pathname = "/"), this.pathname || this.search) {
        var D = this.pathname || "", U = this.search || "";
        this.path = D + U;
      }
      return this.href = this.format(), this;
    }, n.prototype.format = function() {
      var e2 = this.auth || "";
      e2 && (e2 = encodeURIComponent(e2), e2 = e2.replace(/%3A/i, ":"), e2 += "@");
      var t2 = this.protocol || "", r2 = this.pathname || "", n2 = this.hash || "", i2 = false, o2 = "";
      this.host ? i2 = e2 + this.host : this.hostname && (i2 = e2 + (-1 === this.hostname.indexOf(":") ? this.hostname : "[" + this.hostname + "]"), this.port && (i2 += ":" + this.port)), this.query && c(this.query) && Object.keys(this.query).length && (o2 = x.stringify(this.query));
      var s2 = this.search || o2 && "?" + o2 || "";
      return t2 && ":" !== t2.substr(-1) && (t2 += ":"), this.slashes || (!t2 || C[t2]) && false !== i2 ? (i2 = "//" + (i2 || ""), r2 && "/" !== r2.charAt(0) && (r2 = "/" + r2)) : i2 || (i2 = ""), n2 && "#" !== n2.charAt(0) && (n2 = "#" + n2), s2 && "?" !== s2.charAt(0) && (s2 = "?" + s2), r2 = r2.replace(/[?#]/g, function(e3) {
        return encodeURIComponent(e3);
      }), s2 = s2.replace("#", "%23"), t2 + i2 + r2 + s2 + n2;
    }, n.prototype.resolve = function(e2) {
      return this.resolveObject(i(e2, false, true)).format();
    }, n.prototype.resolveObject = function(e2) {
      if (u(e2)) {
        var t2 = new n();
        t2.parse(e2, false, true), e2 = t2;
      }
      var r2 = new n();
      if (Object.keys(this).forEach(function(e3) {
        r2[e3] = this[e3];
      }, this), r2.hash = e2.hash, "" === e2.href)
        return r2.href = r2.format(), r2;
      if (e2.slashes && !e2.protocol)
        return Object.keys(e2).forEach(function(t3) {
          "protocol" !== t3 && (r2[t3] = e2[t3]);
        }), C[r2.protocol] && r2.hostname && !r2.pathname && (r2.path = r2.pathname = "/"), r2.href = r2.format(), r2;
      if (e2.protocol && e2.protocol !== r2.protocol) {
        if (!C[e2.protocol])
          return Object.keys(e2).forEach(function(t3) {
            r2[t3] = e2[t3];
          }), r2.href = r2.format(), r2;
        if (r2.protocol = e2.protocol, e2.host || S[e2.protocol])
          r2.pathname = e2.pathname;
        else {
          for (var i2 = (e2.pathname || "").split("/"); i2.length && !(e2.host = i2.shift()); )
            ;
          e2.host || (e2.host = ""), e2.hostname || (e2.hostname = ""), "" !== i2[0] && i2.unshift(""), i2.length < 2 && i2.unshift(""), r2.pathname = i2.join("/");
        }
        if (r2.search = e2.search, r2.query = e2.query, r2.host = e2.host || "", r2.auth = e2.auth, r2.hostname = e2.hostname || e2.host, r2.port = e2.port, r2.pathname || r2.search) {
          var o2 = r2.pathname || "", s2 = r2.search || "";
          r2.path = o2 + s2;
        }
        return r2.slashes = r2.slashes || e2.slashes, r2.href = r2.format(), r2;
      }
      var a2 = r2.pathname && "/" === r2.pathname.charAt(0), c2 = e2.host || e2.pathname && "/" === e2.pathname.charAt(0), p2 = c2 || a2 || r2.host && e2.pathname, f2 = p2, d2 = r2.pathname && r2.pathname.split("/") || [], i2 = e2.pathname && e2.pathname.split("/") || [], m2 = r2.protocol && !C[r2.protocol];
      if (m2 && (r2.hostname = "", r2.port = null, r2.host && ("" === d2[0] ? d2[0] = r2.host : d2.unshift(r2.host)), r2.host = "", e2.protocol && (e2.hostname = null, e2.port = null, e2.host && ("" === i2[0] ? i2[0] = e2.host : i2.unshift(e2.host)), e2.host = null), p2 = p2 && ("" === i2[0] || "" === d2[0])), c2)
        r2.host = e2.host || "" === e2.host ? e2.host : r2.host, r2.hostname = e2.hostname || "" === e2.hostname ? e2.hostname : r2.hostname, r2.search = e2.search, r2.query = e2.query, d2 = i2;
      else if (i2.length)
        d2 || (d2 = []), d2.pop(), d2 = d2.concat(i2), r2.search = e2.search, r2.query = e2.query;
      else if (!h(e2.search)) {
        if (m2) {
          r2.hostname = r2.host = d2.shift();
          var v2 = !!(r2.host && r2.host.indexOf("@") > 0) && r2.host.split("@");
          v2 && (r2.auth = v2.shift(), r2.host = r2.hostname = v2.shift());
        }
        return r2.search = e2.search, r2.query = e2.query, l(r2.pathname) && l(r2.search) || (r2.path = (r2.pathname ? r2.pathname : "") + (r2.search ? r2.search : "")), r2.href = r2.format(), r2;
      }
      if (!d2.length)
        return r2.pathname = null, r2.search ? r2.path = "/" + r2.search : r2.path = null, r2.href = r2.format(), r2;
      for (var g2 = d2.slice(-1)[0], y2 = (r2.host || e2.host) && ("." === g2 || ".." === g2) || "" === g2, b2 = 0, w2 = d2.length; w2 >= 0; w2--)
        g2 = d2[w2], "." == g2 ? d2.splice(w2, 1) : ".." === g2 ? (d2.splice(w2, 1), b2++) : b2 && (d2.splice(w2, 1), b2--);
      if (!p2 && !f2)
        for (; b2--; b2)
          d2.unshift("..");
      !p2 || "" === d2[0] || d2[0] && "/" === d2[0].charAt(0) || d2.unshift(""), y2 && "/" !== d2.join("/").substr(-1) && d2.push("");
      var E2 = "" === d2[0] || d2[0] && "/" === d2[0].charAt(0);
      if (m2) {
        r2.hostname = r2.host = E2 ? "" : d2.length ? d2.shift() : "";
        var v2 = !!(r2.host && r2.host.indexOf("@") > 0) && r2.host.split("@");
        v2 && (r2.auth = v2.shift(), r2.host = r2.hostname = v2.shift());
      }
      return p2 = p2 || r2.host && d2.length, p2 && !E2 && d2.unshift(""), d2.length ? r2.pathname = d2.join("/") : (r2.pathname = null, r2.path = null), l(r2.pathname) && l(r2.search) || (r2.path = (r2.pathname ? r2.pathname : "") + (r2.search ? r2.search : "")), r2.auth = e2.auth || r2.auth, r2.slashes = r2.slashes || e2.slashes, r2.href = r2.format(), r2;
    }, n.prototype.parseHost = function() {
      var e2 = this.host, t2 = d.exec(e2);
      t2 && (t2 = t2[0], ":" !== t2 && (this.port = t2.substr(1)), e2 = e2.substr(0, e2.length - t2.length)), e2 && (this.hostname = e2);
    };
  }, {punycode: 9, querystring: 12}], 15: [function(e, t, r) {
    arguments[4][12][0].apply(r, arguments);
  }, {"./decode": 13, "./encode": 14, dup: 12}], 14: [function(e, t, r) {
    "use strict";
    var n = function(e2) {
      switch (typeof e2) {
        case "string":
          return e2;
        case "boolean":
          return e2 ? "true" : "false";
        case "number":
          return isFinite(e2) ? e2 : "";
        default:
          return "";
      }
    };
    t.exports = function(e2, t2, r2, i) {
      return t2 = t2 || "&", r2 = r2 || "=", null === e2 && (e2 = void 0), "object" == typeof e2 ? Object.keys(e2).map(function(i2) {
        var o = encodeURIComponent(n(i2)) + r2;
        return Array.isArray(e2[i2]) ? e2[i2].map(function(e3) {
          return o + encodeURIComponent(n(e3));
        }).join(t2) : o + encodeURIComponent(n(e2[i2]));
      }).join(t2) : i ? encodeURIComponent(n(i)) + r2 + encodeURIComponent(n(e2)) : "";
    };
  }, {}], 13: [function(e, t, r) {
    "use strict";
    function n(e2, t2) {
      return Object.prototype.hasOwnProperty.call(e2, t2);
    }
    t.exports = function(e2, t2, r2, i) {
      t2 = t2 || "&", r2 = r2 || "=";
      var o = {};
      if ("string" != typeof e2 || 0 === e2.length)
        return o;
      var s = /\+/g;
      e2 = e2.split(t2);
      var a = 1e3;
      i && "number" == typeof i.maxKeys && (a = i.maxKeys);
      var u = e2.length;
      a > 0 && u > a && (u = a);
      for (var c = 0; c < u; ++c) {
        var l, h, p, f, d = e2[c].replace(s, "%20"), m = d.indexOf(r2);
        m >= 0 ? (l = d.substr(0, m), h = d.substr(m + 1)) : (l = d, h = ""), p = decodeURIComponent(l), f = decodeURIComponent(h), n(o, p) ? Array.isArray(o[p]) ? o[p].push(f) : o[p] = [o[p], f] : o[p] = f;
      }
      return o;
    };
  }, {}], 12: [function(e, t, r) {
    "use strict";
    r.decode = r.parse = e("./decode"), r.encode = r.stringify = e("./encode");
  }, {"./decode": 10, "./encode": 11}], 11: [function(e, t, r) {
    "use strict";
    function n(e2, t2) {
      if (e2.map)
        return e2.map(t2);
      for (var r2 = [], n2 = 0; n2 < e2.length; n2++)
        r2.push(t2(e2[n2], n2));
      return r2;
    }
    var i = function(e2) {
      switch (typeof e2) {
        case "string":
          return e2;
        case "boolean":
          return e2 ? "true" : "false";
        case "number":
          return isFinite(e2) ? e2 : "";
        default:
          return "";
      }
    };
    t.exports = function(e2, t2, r2, a) {
      return t2 = t2 || "&", r2 = r2 || "=", null === e2 && (e2 = void 0), "object" == typeof e2 ? n(s(e2), function(s2) {
        var a2 = encodeURIComponent(i(s2)) + r2;
        return o(e2[s2]) ? n(e2[s2], function(e3) {
          return a2 + encodeURIComponent(i(e3));
        }).join(t2) : a2 + encodeURIComponent(i(e2[s2]));
      }).join(t2) : a ? encodeURIComponent(i(a)) + r2 + encodeURIComponent(i(e2)) : "";
    };
    var o = Array.isArray || function(e2) {
      return "[object Array]" === Object.prototype.toString.call(e2);
    }, s = Object.keys || function(e2) {
      var t2 = [];
      for (var r2 in e2)
        Object.prototype.hasOwnProperty.call(e2, r2) && t2.push(r2);
      return t2;
    };
  }, {}], 10: [function(e, t, r) {
    "use strict";
    function n(e2, t2) {
      return Object.prototype.hasOwnProperty.call(e2, t2);
    }
    t.exports = function(e2, t2, r2, o) {
      t2 = t2 || "&", r2 = r2 || "=";
      var s = {};
      if ("string" != typeof e2 || 0 === e2.length)
        return s;
      var a = /\+/g;
      e2 = e2.split(t2);
      var u = 1e3;
      o && "number" == typeof o.maxKeys && (u = o.maxKeys);
      var c = e2.length;
      u > 0 && c > u && (c = u);
      for (var l = 0; l < c; ++l) {
        var h, p, f, d, m = e2[l].replace(a, "%20"), v = m.indexOf(r2);
        v >= 0 ? (h = m.substr(0, v), p = m.substr(v + 1)) : (h = m, p = ""), f = decodeURIComponent(h), d = decodeURIComponent(p), n(s, f) ? i(s[f]) ? s[f].push(d) : s[f] = [s[f], d] : s[f] = d;
      }
      return s;
    };
    var i = Array.isArray || function(e2) {
      return "[object Array]" === Object.prototype.toString.call(e2);
    };
  }, {}], 9: [function(e, t, r) {
    (function(e2) {
      !function(n) {
        function i(e3) {
          throw RangeError(q[e3]);
        }
        function o(e3, t2) {
          for (var r2 = e3.length, n2 = []; r2--; )
            n2[r2] = t2(e3[r2]);
          return n2;
        }
        function s(e3, t2) {
          var r2 = e3.split("@"), n2 = "";
          return r2.length > 1 && (n2 = r2[0] + "@", e3 = r2[1]), e3 = e3.replace(P, "."), n2 + o(e3.split("."), t2).join(".");
        }
        function a(e3) {
          for (var t2, r2, n2 = [], i2 = 0, o2 = e3.length; i2 < o2; )
            t2 = e3.charCodeAt(i2++), t2 >= 55296 && t2 <= 56319 && i2 < o2 ? (r2 = e3.charCodeAt(i2++), 56320 == (64512 & r2) ? n2.push(((1023 & t2) << 10) + (1023 & r2) + 65536) : (n2.push(t2), i2--)) : n2.push(t2);
          return n2;
        }
        function u(e3) {
          return o(e3, function(e4) {
            var t2 = "";
            return e4 > 65535 && (e4 -= 65536, t2 += U(e4 >>> 10 & 1023 | 55296), e4 = 56320 | 1023 & e4), t2 += U(e4);
          }).join("");
        }
        function c(e3) {
          return e3 - 48 < 10 ? e3 - 22 : e3 - 65 < 26 ? e3 - 65 : e3 - 97 < 26 ? e3 - 97 : _;
        }
        function l(e3, t2) {
          return e3 + 22 + 75 * (e3 < 26) - ((0 != t2) << 5);
        }
        function h(e3, t2, r2) {
          var n2 = 0;
          for (e3 = r2 ? N(e3 / R) : e3 >> 1, e3 += N(e3 / t2); e3 > O * C >> 1; n2 += _)
            e3 = N(e3 / O);
          return N(n2 + (O + 1) * e3 / (e3 + x));
        }
        function p(e3) {
          var t2, r2, n2, o2, s2, a2, l2, p2, f2, d2, m2 = [], v2 = e3.length, g2 = 0, y2 = T, b2 = A;
          for (r2 = e3.lastIndexOf(k), r2 < 0 && (r2 = 0), n2 = 0; n2 < r2; ++n2)
            e3.charCodeAt(n2) >= 128 && i("not-basic"), m2.push(e3.charCodeAt(n2));
          for (o2 = r2 > 0 ? r2 + 1 : 0; o2 < v2; ) {
            for (s2 = g2, a2 = 1, l2 = _; o2 >= v2 && i("invalid-input"), p2 = c(e3.charCodeAt(o2++)), (p2 >= _ || p2 > N((E - g2) / a2)) && i("overflow"), g2 += p2 * a2, f2 = l2 <= b2 ? S : l2 >= b2 + C ? C : l2 - b2, !(p2 < f2); l2 += _)
              d2 = _ - f2, a2 > N(E / d2) && i("overflow"), a2 *= d2;
            t2 = m2.length + 1, b2 = h(g2 - s2, t2, 0 == s2), N(g2 / t2) > E - y2 && i("overflow"), y2 += N(g2 / t2), g2 %= t2, m2.splice(g2++, 0, y2);
          }
          return u(m2);
        }
        function f(e3) {
          var t2, r2, n2, o2, s2, u2, c2, p2, f2, d2, m2, v2, g2, y2, b2, w2 = [];
          for (e3 = a(e3), v2 = e3.length, t2 = T, r2 = 0, s2 = A, u2 = 0; u2 < v2; ++u2)
            (m2 = e3[u2]) < 128 && w2.push(U(m2));
          for (n2 = o2 = w2.length, o2 && w2.push(k); n2 < v2; ) {
            for (c2 = E, u2 = 0; u2 < v2; ++u2)
              (m2 = e3[u2]) >= t2 && m2 < c2 && (c2 = m2);
            for (g2 = n2 + 1, c2 - t2 > N((E - r2) / g2) && i("overflow"), r2 += (c2 - t2) * g2, t2 = c2, u2 = 0; u2 < v2; ++u2)
              if (m2 = e3[u2], m2 < t2 && ++r2 > E && i("overflow"), m2 == t2) {
                for (p2 = r2, f2 = _; d2 = f2 <= s2 ? S : f2 >= s2 + C ? C : f2 - s2, !(p2 < d2); f2 += _)
                  b2 = p2 - d2, y2 = _ - d2, w2.push(U(l(d2 + b2 % y2, 0))), p2 = N(b2 / y2);
                w2.push(U(l(p2, 0))), s2 = h(r2, g2, n2 == o2), r2 = 0, ++n2;
              }
            ++r2, ++t2;
          }
          return w2.join("");
        }
        function d(e3) {
          return s(e3, function(e4) {
            return I.test(e4) ? p(e4.slice(4).toLowerCase()) : e4;
          });
        }
        function m(e3) {
          return s(e3, function(e4) {
            return L.test(e4) ? "xn--" + f(e4) : e4;
          });
        }
        var v = "object" == typeof r && r && !r.nodeType && r, g = "object" == typeof t && t && !t.nodeType && t, y = "object" == typeof e2 && e2;
        y.global !== y && y.window !== y && y.self !== y || (n = y);
        var b, w, E = 2147483647, _ = 36, S = 1, C = 26, x = 38, R = 700, A = 72, T = 128, k = "-", I = /^xn--/, L = /[^\x20-\x7E]/, P = /[\x2E\u3002\uFF0E\uFF61]/g, q = {overflow: "Overflow: input needs wider integers to process", "not-basic": "Illegal input >= 0x80 (not a basic code point)", "invalid-input": "Invalid input"}, O = _ - S, N = Math.floor, U = String.fromCharCode;
        if (b = {version: "1.3.2", ucs2: {decode: a, encode: u}, decode: p, encode: f, toASCII: m, toUnicode: d}, "function" == typeof define && "object" == typeof define.amd && define.amd)
          define("punycode", function() {
            return b;
          });
        else if (v && g)
          if (t.exports == v)
            g.exports = b;
          else
            for (w in b)
              b.hasOwnProperty(w) && (v[w] = b[w]);
        else
          n.punycode = b;
      }(this);
    }).call(this, "undefined" != typeof window ? window : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {});
  }, {}], 4: [function(e, t, r) {
    function n() {
      this._events = this._events || {}, this._maxListeners = this._maxListeners || void 0;
    }
    function i(e2) {
      return "function" == typeof e2;
    }
    function o(e2) {
      return "number" == typeof e2;
    }
    function s(e2) {
      return "object" == typeof e2 && null !== e2;
    }
    function a(e2) {
      return void 0 === e2;
    }
    t.exports = n, n.EventEmitter = n, n.prototype._events = void 0, n.prototype._maxListeners = void 0, n.defaultMaxListeners = 10, n.prototype.setMaxListeners = function(e2) {
      if (!o(e2) || e2 < 0 || isNaN(e2))
        throw TypeError("n must be a positive number");
      return this._maxListeners = e2, this;
    }, n.prototype.emit = function(e2) {
      var t2, r2, n2, o2, u, c;
      if (this._events || (this._events = {}), "error" === e2 && (!this._events.error || s(this._events.error) && !this._events.error.length)) {
        if ((t2 = arguments[1]) instanceof Error)
          throw t2;
        var l = new Error('Uncaught, unspecified "error" event. (' + t2 + ")");
        throw l.context = t2, l;
      }
      if (r2 = this._events[e2], a(r2))
        return false;
      if (i(r2))
        switch (arguments.length) {
          case 1:
            r2.call(this);
            break;
          case 2:
            r2.call(this, arguments[1]);
            break;
          case 3:
            r2.call(this, arguments[1], arguments[2]);
            break;
          default:
            o2 = Array.prototype.slice.call(arguments, 1), r2.apply(this, o2);
        }
      else if (s(r2))
        for (o2 = Array.prototype.slice.call(arguments, 1), c = r2.slice(), n2 = c.length, u = 0; u < n2; u++)
          c[u].apply(this, o2);
      return true;
    }, n.prototype.addListener = function(e2, t2) {
      var r2;
      if (!i(t2))
        throw TypeError("listener must be a function");
      return this._events || (this._events = {}), this._events.newListener && this.emit("newListener", e2, i(t2.listener) ? t2.listener : t2), this._events[e2] ? s(this._events[e2]) ? this._events[e2].push(t2) : this._events[e2] = [this._events[e2], t2] : this._events[e2] = t2, s(this._events[e2]) && !this._events[e2].warned && (r2 = a(this._maxListeners) ? n.defaultMaxListeners : this._maxListeners) && r2 > 0 && this._events[e2].length > r2 && (this._events[e2].warned = true, console.error("(node) warning: possible EventEmitter memory leak detected. %d listeners added. Use emitter.setMaxListeners() to increase limit.", this._events[e2].length), "function" == typeof console.trace && console.trace()), this;
    }, n.prototype.on = n.prototype.addListener, n.prototype.once = function(e2, t2) {
      function r2() {
        this.removeListener(e2, r2), n2 || (n2 = true, t2.apply(this, arguments));
      }
      if (!i(t2))
        throw TypeError("listener must be a function");
      var n2 = false;
      return r2.listener = t2, this.on(e2, r2), this;
    }, n.prototype.removeListener = function(e2, t2) {
      var r2, n2, o2, a2;
      if (!i(t2))
        throw TypeError("listener must be a function");
      if (!this._events || !this._events[e2])
        return this;
      if (r2 = this._events[e2], o2 = r2.length, n2 = -1, r2 === t2 || i(r2.listener) && r2.listener === t2)
        delete this._events[e2], this._events.removeListener && this.emit("removeListener", e2, t2);
      else if (s(r2)) {
        for (a2 = o2; a2-- > 0; )
          if (r2[a2] === t2 || r2[a2].listener && r2[a2].listener === t2) {
            n2 = a2;
            break;
          }
        if (n2 < 0)
          return this;
        1 === r2.length ? (r2.length = 0, delete this._events[e2]) : r2.splice(n2, 1), this._events.removeListener && this.emit("removeListener", e2, t2);
      }
      return this;
    }, n.prototype.removeAllListeners = function(e2) {
      var t2, r2;
      if (!this._events)
        return this;
      if (!this._events.removeListener)
        return 0 === arguments.length ? this._events = {} : this._events[e2] && delete this._events[e2], this;
      if (0 === arguments.length) {
        for (t2 in this._events)
          "removeListener" !== t2 && this.removeAllListeners(t2);
        return this.removeAllListeners("removeListener"), this._events = {}, this;
      }
      if (r2 = this._events[e2], i(r2))
        this.removeListener(e2, r2);
      else if (r2)
        for (; r2.length; )
          this.removeListener(e2, r2[r2.length - 1]);
      return delete this._events[e2], this;
    }, n.prototype.listeners = function(e2) {
      return this._events && this._events[e2] ? i(this._events[e2]) ? [this._events[e2]] : this._events[e2].slice() : [];
    }, n.prototype.listenerCount = function(e2) {
      if (this._events) {
        var t2 = this._events[e2];
        if (i(t2))
          return 1;
        if (t2)
          return t2.length;
      }
      return 0;
    }, n.listenerCount = function(e2, t2) {
      return e2.listenerCount(t2);
    };
  }, {}], 3: [function(e, t, r) {
    (function(t2, n) {
      "use strict";
      function i() {
        return n.TYPED_ARRAY_SUPPORT ? 2147483647 : 1073741823;
      }
      function o(e2, t3) {
        if (i() < t3)
          throw new RangeError("Invalid typed array length");
        return n.TYPED_ARRAY_SUPPORT ? (e2 = new Uint8Array(t3), e2.__proto__ = n.prototype) : (null === e2 && (e2 = new n(t3)), e2.length = t3), e2;
      }
      function n(e2, t3, r2) {
        if (!(n.TYPED_ARRAY_SUPPORT || this instanceof n))
          return new n(e2, t3, r2);
        if ("number" == typeof e2) {
          if ("string" == typeof t3)
            throw new Error("If encoding is specified then the first argument must be a string");
          return c(this, e2);
        }
        return s(this, e2, t3, r2);
      }
      function s(e2, t3, r2, n2) {
        if ("number" == typeof t3)
          throw new TypeError('"value" argument must not be a number');
        return "undefined" != typeof ArrayBuffer && t3 instanceof ArrayBuffer ? p(e2, t3, r2, n2) : "string" == typeof t3 ? l(e2, t3, r2) : f(e2, t3);
      }
      function a(e2) {
        if ("number" != typeof e2)
          throw new TypeError('"size" argument must be a number');
        if (e2 < 0)
          throw new RangeError('"size" argument must not be negative');
      }
      function u(e2, t3, r2, n2) {
        return a(t3), t3 <= 0 ? o(e2, t3) : void 0 !== r2 ? "string" == typeof n2 ? o(e2, t3).fill(r2, n2) : o(e2, t3).fill(r2) : o(e2, t3);
      }
      function c(e2, t3) {
        if (a(t3), e2 = o(e2, t3 < 0 ? 0 : 0 | d(t3)), !n.TYPED_ARRAY_SUPPORT)
          for (var r2 = 0; r2 < t3; ++r2)
            e2[r2] = 0;
        return e2;
      }
      function l(e2, t3, r2) {
        if ("string" == typeof r2 && "" !== r2 || (r2 = "utf8"), !n.isEncoding(r2))
          throw new TypeError('"encoding" must be a valid string encoding');
        var i2 = 0 | v(t3, r2);
        e2 = o(e2, i2);
        var s2 = e2.write(t3, r2);
        return s2 !== i2 && (e2 = e2.slice(0, s2)), e2;
      }
      function h(e2, t3) {
        var r2 = t3.length < 0 ? 0 : 0 | d(t3.length);
        e2 = o(e2, r2);
        for (var n2 = 0; n2 < r2; n2 += 1)
          e2[n2] = 255 & t3[n2];
        return e2;
      }
      function p(e2, t3, r2, i2) {
        if (t3.byteLength, r2 < 0 || t3.byteLength < r2)
          throw new RangeError("'offset' is out of bounds");
        if (t3.byteLength < r2 + (i2 || 0))
          throw new RangeError("'length' is out of bounds");
        return t3 = void 0 === r2 && void 0 === i2 ? new Uint8Array(t3) : void 0 === i2 ? new Uint8Array(t3, r2) : new Uint8Array(t3, r2, i2), n.TYPED_ARRAY_SUPPORT ? (e2 = t3, e2.__proto__ = n.prototype) : e2 = h(e2, t3), e2;
      }
      function f(e2, t3) {
        if (n.isBuffer(t3)) {
          var r2 = 0 | d(t3.length);
          return e2 = o(e2, r2), 0 === e2.length ? e2 : (t3.copy(e2, 0, 0, r2), e2);
        }
        if (t3) {
          if ("undefined" != typeof ArrayBuffer && t3.buffer instanceof ArrayBuffer || "length" in t3)
            return "number" != typeof t3.length || G(t3.length) ? o(e2, 0) : h(e2, t3);
          if ("Buffer" === t3.type && Q(t3.data))
            return h(e2, t3.data);
        }
        throw new TypeError("First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.");
      }
      function d(e2) {
        if (e2 >= i())
          throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + i().toString(16) + " bytes");
        return 0 | e2;
      }
      function m(e2) {
        return +e2 != e2 && (e2 = 0), n.alloc(+e2);
      }
      function v(e2, t3) {
        if (n.isBuffer(e2))
          return e2.length;
        if ("undefined" != typeof ArrayBuffer && "function" == typeof ArrayBuffer.isView && (ArrayBuffer.isView(e2) || e2 instanceof ArrayBuffer))
          return e2.byteLength;
        "string" != typeof e2 && (e2 = "" + e2);
        var r2 = e2.length;
        if (0 === r2)
          return 0;
        for (var i2 = false; ; )
          switch (t3) {
            case "ascii":
            case "latin1":
            case "binary":
              return r2;
            case "utf8":
            case "utf-8":
            case void 0:
              return V(e2).length;
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return 2 * r2;
            case "hex":
              return r2 >>> 1;
            case "base64":
              return X(e2).length;
            default:
              if (i2)
                return V(e2).length;
              t3 = ("" + t3).toLowerCase(), i2 = true;
          }
      }
      function g(e2, t3, r2) {
        var n2 = false;
        if ((void 0 === t3 || t3 < 0) && (t3 = 0), t3 > this.length)
          return "";
        if ((void 0 === r2 || r2 > this.length) && (r2 = this.length), r2 <= 0)
          return "";
        if (r2 >>>= 0, t3 >>>= 0, r2 <= t3)
          return "";
        for (e2 || (e2 = "utf8"); ; )
          switch (e2) {
            case "hex":
              return P(this, t3, r2);
            case "utf8":
            case "utf-8":
              return T(this, t3, r2);
            case "ascii":
              return I(this, t3, r2);
            case "latin1":
            case "binary":
              return L(this, t3, r2);
            case "base64":
              return A(this, t3, r2);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return q(this, t3, r2);
            default:
              if (n2)
                throw new TypeError("Unknown encoding: " + e2);
              e2 = (e2 + "").toLowerCase(), n2 = true;
          }
      }
      function y(e2, t3, r2) {
        var n2 = e2[t3];
        e2[t3] = e2[r2], e2[r2] = n2;
      }
      function b(e2, t3, r2, i2, o2) {
        if (0 === e2.length)
          return -1;
        if ("string" == typeof r2 ? (i2 = r2, r2 = 0) : r2 > 2147483647 ? r2 = 2147483647 : r2 < -2147483648 && (r2 = -2147483648), r2 = +r2, isNaN(r2) && (r2 = o2 ? 0 : e2.length - 1), r2 < 0 && (r2 = e2.length + r2), r2 >= e2.length) {
          if (o2)
            return -1;
          r2 = e2.length - 1;
        } else if (r2 < 0) {
          if (!o2)
            return -1;
          r2 = 0;
        }
        if ("string" == typeof t3 && (t3 = n.from(t3, i2)), n.isBuffer(t3))
          return 0 === t3.length ? -1 : w(e2, t3, r2, i2, o2);
        if ("number" == typeof t3)
          return t3 &= 255, n.TYPED_ARRAY_SUPPORT && "function" == typeof Uint8Array.prototype.indexOf ? o2 ? Uint8Array.prototype.indexOf.call(e2, t3, r2) : Uint8Array.prototype.lastIndexOf.call(e2, t3, r2) : w(e2, [t3], r2, i2, o2);
        throw new TypeError("val must be string, number or Buffer");
      }
      function w(e2, t3, r2, n2, i2) {
        function o2(e3, t4) {
          return 1 === s2 ? e3[t4] : e3.readUInt16BE(t4 * s2);
        }
        var s2 = 1, a2 = e2.length, u2 = t3.length;
        if (void 0 !== n2 && ("ucs2" === (n2 = String(n2).toLowerCase()) || "ucs-2" === n2 || "utf16le" === n2 || "utf-16le" === n2)) {
          if (e2.length < 2 || t3.length < 2)
            return -1;
          s2 = 2, a2 /= 2, u2 /= 2, r2 /= 2;
        }
        var c2;
        if (i2) {
          var l2 = -1;
          for (c2 = r2; c2 < a2; c2++)
            if (o2(e2, c2) === o2(t3, -1 === l2 ? 0 : c2 - l2)) {
              if (-1 === l2 && (l2 = c2), c2 - l2 + 1 === u2)
                return l2 * s2;
            } else
              -1 !== l2 && (c2 -= c2 - l2), l2 = -1;
        } else
          for (r2 + u2 > a2 && (r2 = a2 - u2), c2 = r2; c2 >= 0; c2--) {
            for (var h2 = true, p2 = 0; p2 < u2; p2++)
              if (o2(e2, c2 + p2) !== o2(t3, p2)) {
                h2 = false;
                break;
              }
            if (h2)
              return c2;
          }
        return -1;
      }
      function E(e2, t3, r2, n2) {
        r2 = Number(r2) || 0;
        var i2 = e2.length - r2;
        n2 ? (n2 = Number(n2)) > i2 && (n2 = i2) : n2 = i2;
        var o2 = t3.length;
        if (o2 % 2 != 0)
          throw new TypeError("Invalid hex string");
        n2 > o2 / 2 && (n2 = o2 / 2);
        for (var s2 = 0; s2 < n2; ++s2) {
          var a2 = parseInt(t3.substr(2 * s2, 2), 16);
          if (isNaN(a2))
            return s2;
          e2[r2 + s2] = a2;
        }
        return s2;
      }
      function _(e2, t3, r2, n2) {
        return Y(V(t3, e2.length - r2), e2, r2, n2);
      }
      function S(e2, t3, r2, n2) {
        return Y(K(t3), e2, r2, n2);
      }
      function C(e2, t3, r2, n2) {
        return S(e2, t3, r2, n2);
      }
      function x(e2, t3, r2, n2) {
        return Y(X(t3), e2, r2, n2);
      }
      function R(e2, t3, r2, n2) {
        return Y(W(t3, e2.length - r2), e2, r2, n2);
      }
      function A(e2, t3, r2) {
        return 0 === t3 && r2 === e2.length ? J.fromByteArray(e2) : J.fromByteArray(e2.slice(t3, r2));
      }
      function T(e2, t3, r2) {
        r2 = Math.min(e2.length, r2);
        for (var n2 = [], i2 = t3; i2 < r2; ) {
          var o2 = e2[i2], s2 = null, a2 = o2 > 239 ? 4 : o2 > 223 ? 3 : o2 > 191 ? 2 : 1;
          if (i2 + a2 <= r2) {
            var u2, c2, l2, h2;
            switch (a2) {
              case 1:
                o2 < 128 && (s2 = o2);
                break;
              case 2:
                u2 = e2[i2 + 1], 128 == (192 & u2) && (h2 = (31 & o2) << 6 | 63 & u2) > 127 && (s2 = h2);
                break;
              case 3:
                u2 = e2[i2 + 1], c2 = e2[i2 + 2], 128 == (192 & u2) && 128 == (192 & c2) && (h2 = (15 & o2) << 12 | (63 & u2) << 6 | 63 & c2) > 2047 && (h2 < 55296 || h2 > 57343) && (s2 = h2);
                break;
              case 4:
                u2 = e2[i2 + 1], c2 = e2[i2 + 2], l2 = e2[i2 + 3], 128 == (192 & u2) && 128 == (192 & c2) && 128 == (192 & l2) && (h2 = (15 & o2) << 18 | (63 & u2) << 12 | (63 & c2) << 6 | 63 & l2) > 65535 && h2 < 1114112 && (s2 = h2);
            }
          }
          null === s2 ? (s2 = 65533, a2 = 1) : s2 > 65535 && (s2 -= 65536, n2.push(s2 >>> 10 & 1023 | 55296), s2 = 56320 | 1023 & s2), n2.push(s2), i2 += a2;
        }
        return k(n2);
      }
      function k(e2) {
        var t3 = e2.length;
        if (t3 <= Z)
          return String.fromCharCode.apply(String, e2);
        for (var r2 = "", n2 = 0; n2 < t3; )
          r2 += String.fromCharCode.apply(String, e2.slice(n2, n2 += Z));
        return r2;
      }
      function I(e2, t3, r2) {
        var n2 = "";
        r2 = Math.min(e2.length, r2);
        for (var i2 = t3; i2 < r2; ++i2)
          n2 += String.fromCharCode(127 & e2[i2]);
        return n2;
      }
      function L(e2, t3, r2) {
        var n2 = "";
        r2 = Math.min(e2.length, r2);
        for (var i2 = t3; i2 < r2; ++i2)
          n2 += String.fromCharCode(e2[i2]);
        return n2;
      }
      function P(e2, t3, r2) {
        var n2 = e2.length;
        (!t3 || t3 < 0) && (t3 = 0), (!r2 || r2 < 0 || r2 > n2) && (r2 = n2);
        for (var i2 = "", o2 = t3; o2 < r2; ++o2)
          i2 += z(e2[o2]);
        return i2;
      }
      function q(e2, t3, r2) {
        for (var n2 = e2.slice(t3, r2), i2 = "", o2 = 0; o2 < n2.length; o2 += 2)
          i2 += String.fromCharCode(n2[o2] + 256 * n2[o2 + 1]);
        return i2;
      }
      function O(e2, t3, r2) {
        if (e2 % 1 != 0 || e2 < 0)
          throw new RangeError("offset is not uint");
        if (e2 + t3 > r2)
          throw new RangeError("Trying to access beyond buffer length");
      }
      function N(e2, t3, r2, i2, o2, s2) {
        if (!n.isBuffer(e2))
          throw new TypeError('"buffer" argument must be a Buffer instance');
        if (t3 > o2 || t3 < s2)
          throw new RangeError('"value" argument is out of bounds');
        if (r2 + i2 > e2.length)
          throw new RangeError("Index out of range");
      }
      function U(e2, t3, r2, n2) {
        t3 < 0 && (t3 = 65535 + t3 + 1);
        for (var i2 = 0, o2 = Math.min(e2.length - r2, 2); i2 < o2; ++i2)
          e2[r2 + i2] = (t3 & 255 << 8 * (n2 ? i2 : 1 - i2)) >>> 8 * (n2 ? i2 : 1 - i2);
      }
      function D(e2, t3, r2, n2) {
        t3 < 0 && (t3 = 4294967295 + t3 + 1);
        for (var i2 = 0, o2 = Math.min(e2.length - r2, 4); i2 < o2; ++i2)
          e2[r2 + i2] = t3 >>> 8 * (n2 ? i2 : 3 - i2) & 255;
      }
      function M(e2, t3, r2, n2, i2, o2) {
        if (r2 + n2 > e2.length)
          throw new RangeError("Index out of range");
        if (r2 < 0)
          throw new RangeError("Index out of range");
      }
      function j(e2, t3, r2, n2, i2) {
        return i2 || M(e2, t3, r2, 4, 34028234663852886e22, -34028234663852886e22), $.write(e2, t3, r2, n2, 23, 4), r2 + 4;
      }
      function B(e2, t3, r2, n2, i2) {
        return i2 || M(e2, t3, r2, 8, 17976931348623157e292, -17976931348623157e292), $.write(e2, t3, r2, n2, 52, 8), r2 + 8;
      }
      function F(e2) {
        if (e2 = H(e2).replace(ee, ""), e2.length < 2)
          return "";
        for (; e2.length % 4 != 0; )
          e2 += "=";
        return e2;
      }
      function H(e2) {
        return e2.trim ? e2.trim() : e2.replace(/^\s+|\s+$/g, "");
      }
      function z(e2) {
        return e2 < 16 ? "0" + e2.toString(16) : e2.toString(16);
      }
      function V(e2, t3) {
        t3 = t3 || 1 / 0;
        for (var r2, n2 = e2.length, i2 = null, o2 = [], s2 = 0; s2 < n2; ++s2) {
          if ((r2 = e2.charCodeAt(s2)) > 55295 && r2 < 57344) {
            if (!i2) {
              if (r2 > 56319) {
                (t3 -= 3) > -1 && o2.push(239, 191, 189);
                continue;
              }
              if (s2 + 1 === n2) {
                (t3 -= 3) > -1 && o2.push(239, 191, 189);
                continue;
              }
              i2 = r2;
              continue;
            }
            if (r2 < 56320) {
              (t3 -= 3) > -1 && o2.push(239, 191, 189), i2 = r2;
              continue;
            }
            r2 = 65536 + (i2 - 55296 << 10 | r2 - 56320);
          } else
            i2 && (t3 -= 3) > -1 && o2.push(239, 191, 189);
          if (i2 = null, r2 < 128) {
            if ((t3 -= 1) < 0)
              break;
            o2.push(r2);
          } else if (r2 < 2048) {
            if ((t3 -= 2) < 0)
              break;
            o2.push(r2 >> 6 | 192, 63 & r2 | 128);
          } else if (r2 < 65536) {
            if ((t3 -= 3) < 0)
              break;
            o2.push(r2 >> 12 | 224, r2 >> 6 & 63 | 128, 63 & r2 | 128);
          } else {
            if (!(r2 < 1114112))
              throw new Error("Invalid code point");
            if ((t3 -= 4) < 0)
              break;
            o2.push(r2 >> 18 | 240, r2 >> 12 & 63 | 128, r2 >> 6 & 63 | 128, 63 & r2 | 128);
          }
        }
        return o2;
      }
      function K(e2) {
        for (var t3 = [], r2 = 0; r2 < e2.length; ++r2)
          t3.push(255 & e2.charCodeAt(r2));
        return t3;
      }
      function W(e2, t3) {
        for (var r2, n2, i2, o2 = [], s2 = 0; s2 < e2.length && !((t3 -= 2) < 0); ++s2)
          r2 = e2.charCodeAt(s2), n2 = r2 >> 8, i2 = r2 % 256, o2.push(i2), o2.push(n2);
        return o2;
      }
      function X(e2) {
        return J.toByteArray(F(e2));
      }
      function Y(e2, t3, r2, n2) {
        for (var i2 = 0; i2 < n2 && !(i2 + r2 >= t3.length || i2 >= e2.length); ++i2)
          t3[i2 + r2] = e2[i2];
        return i2;
      }
      function G(e2) {
        return e2 !== e2;
      }
      var J = e("base64-js"), $ = e("ieee754"), Q = e("isarray");
      r.Buffer = n, r.SlowBuffer = m, r.INSPECT_MAX_BYTES = 50, n.TYPED_ARRAY_SUPPORT = void 0 !== t2.TYPED_ARRAY_SUPPORT ? t2.TYPED_ARRAY_SUPPORT : function() {
        try {
          var e2 = new Uint8Array(1);
          return e2.__proto__ = {__proto__: Uint8Array.prototype, foo: function() {
            return 42;
          }}, 42 === e2.foo() && "function" == typeof e2.subarray && 0 === e2.subarray(1, 1).byteLength;
        } catch (e3) {
          return false;
        }
      }(), r.kMaxLength = i(), n.poolSize = 8192, n._augment = function(e2) {
        return e2.__proto__ = n.prototype, e2;
      }, n.from = function(e2, t3, r2) {
        return s(null, e2, t3, r2);
      }, n.TYPED_ARRAY_SUPPORT && (n.prototype.__proto__ = Uint8Array.prototype, n.__proto__ = Uint8Array, "undefined" != typeof Symbol && Symbol.species && n[Symbol.species] === n && Object.defineProperty(n, Symbol.species, {value: null, configurable: true})), n.alloc = function(e2, t3, r2) {
        return u(null, e2, t3, r2);
      }, n.allocUnsafe = function(e2) {
        return c(null, e2);
      }, n.allocUnsafeSlow = function(e2) {
        return c(null, e2);
      }, n.isBuffer = function(e2) {
        return !(null == e2 || !e2._isBuffer);
      }, n.compare = function(e2, t3) {
        if (!n.isBuffer(e2) || !n.isBuffer(t3))
          throw new TypeError("Arguments must be Buffers");
        if (e2 === t3)
          return 0;
        for (var r2 = e2.length, i2 = t3.length, o2 = 0, s2 = Math.min(r2, i2); o2 < s2; ++o2)
          if (e2[o2] !== t3[o2]) {
            r2 = e2[o2], i2 = t3[o2];
            break;
          }
        return r2 < i2 ? -1 : i2 < r2 ? 1 : 0;
      }, n.isEncoding = function(e2) {
        switch (String(e2).toLowerCase()) {
          case "hex":
          case "utf8":
          case "utf-8":
          case "ascii":
          case "latin1":
          case "binary":
          case "base64":
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return true;
          default:
            return false;
        }
      }, n.concat = function(e2, t3) {
        if (!Q(e2))
          throw new TypeError('"list" argument must be an Array of Buffers');
        if (0 === e2.length)
          return n.alloc(0);
        var r2;
        if (void 0 === t3)
          for (t3 = 0, r2 = 0; r2 < e2.length; ++r2)
            t3 += e2[r2].length;
        var i2 = n.allocUnsafe(t3), o2 = 0;
        for (r2 = 0; r2 < e2.length; ++r2) {
          var s2 = e2[r2];
          if (!n.isBuffer(s2))
            throw new TypeError('"list" argument must be an Array of Buffers');
          s2.copy(i2, o2), o2 += s2.length;
        }
        return i2;
      }, n.byteLength = v, n.prototype._isBuffer = true, n.prototype.swap16 = function() {
        var e2 = this.length;
        if (e2 % 2 != 0)
          throw new RangeError("Buffer size must be a multiple of 16-bits");
        for (var t3 = 0; t3 < e2; t3 += 2)
          y(this, t3, t3 + 1);
        return this;
      }, n.prototype.swap32 = function() {
        var e2 = this.length;
        if (e2 % 4 != 0)
          throw new RangeError("Buffer size must be a multiple of 32-bits");
        for (var t3 = 0; t3 < e2; t3 += 4)
          y(this, t3, t3 + 3), y(this, t3 + 1, t3 + 2);
        return this;
      }, n.prototype.swap64 = function() {
        var e2 = this.length;
        if (e2 % 8 != 0)
          throw new RangeError("Buffer size must be a multiple of 64-bits");
        for (var t3 = 0; t3 < e2; t3 += 8)
          y(this, t3, t3 + 7), y(this, t3 + 1, t3 + 6), y(this, t3 + 2, t3 + 5), y(this, t3 + 3, t3 + 4);
        return this;
      }, n.prototype.toString = function() {
        var e2 = 0 | this.length;
        return 0 === e2 ? "" : 0 === arguments.length ? T(this, 0, e2) : g.apply(this, arguments);
      }, n.prototype.equals = function(e2) {
        if (!n.isBuffer(e2))
          throw new TypeError("Argument must be a Buffer");
        return this === e2 || 0 === n.compare(this, e2);
      }, n.prototype.inspect = function() {
        var e2 = "", t3 = r.INSPECT_MAX_BYTES;
        return this.length > 0 && (e2 = this.toString("hex", 0, t3).match(/.{2}/g).join(" "), this.length > t3 && (e2 += " ... ")), "<Buffer " + e2 + ">";
      }, n.prototype.compare = function(e2, t3, r2, i2, o2) {
        if (!n.isBuffer(e2))
          throw new TypeError("Argument must be a Buffer");
        if (void 0 === t3 && (t3 = 0), void 0 === r2 && (r2 = e2 ? e2.length : 0), void 0 === i2 && (i2 = 0), void 0 === o2 && (o2 = this.length), t3 < 0 || r2 > e2.length || i2 < 0 || o2 > this.length)
          throw new RangeError("out of range index");
        if (i2 >= o2 && t3 >= r2)
          return 0;
        if (i2 >= o2)
          return -1;
        if (t3 >= r2)
          return 1;
        if (t3 >>>= 0, r2 >>>= 0, i2 >>>= 0, o2 >>>= 0, this === e2)
          return 0;
        for (var s2 = o2 - i2, a2 = r2 - t3, u2 = Math.min(s2, a2), c2 = this.slice(i2, o2), l2 = e2.slice(t3, r2), h2 = 0; h2 < u2; ++h2)
          if (c2[h2] !== l2[h2]) {
            s2 = c2[h2], a2 = l2[h2];
            break;
          }
        return s2 < a2 ? -1 : a2 < s2 ? 1 : 0;
      }, n.prototype.includes = function(e2, t3, r2) {
        return -1 !== this.indexOf(e2, t3, r2);
      }, n.prototype.indexOf = function(e2, t3, r2) {
        return b(this, e2, t3, r2, true);
      }, n.prototype.lastIndexOf = function(e2, t3, r2) {
        return b(this, e2, t3, r2, false);
      }, n.prototype.write = function(e2, t3, r2, n2) {
        if (void 0 === t3)
          n2 = "utf8", r2 = this.length, t3 = 0;
        else if (void 0 === r2 && "string" == typeof t3)
          n2 = t3, r2 = this.length, t3 = 0;
        else {
          if (!isFinite(t3))
            throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");
          t3 |= 0, isFinite(r2) ? (r2 |= 0, void 0 === n2 && (n2 = "utf8")) : (n2 = r2, r2 = void 0);
        }
        var i2 = this.length - t3;
        if ((void 0 === r2 || r2 > i2) && (r2 = i2), e2.length > 0 && (r2 < 0 || t3 < 0) || t3 > this.length)
          throw new RangeError("Attempt to write outside buffer bounds");
        n2 || (n2 = "utf8");
        for (var o2 = false; ; )
          switch (n2) {
            case "hex":
              return E(this, e2, t3, r2);
            case "utf8":
            case "utf-8":
              return _(this, e2, t3, r2);
            case "ascii":
              return S(this, e2, t3, r2);
            case "latin1":
            case "binary":
              return C(this, e2, t3, r2);
            case "base64":
              return x(this, e2, t3, r2);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return R(this, e2, t3, r2);
            default:
              if (o2)
                throw new TypeError("Unknown encoding: " + n2);
              n2 = ("" + n2).toLowerCase(), o2 = true;
          }
      }, n.prototype.toJSON = function() {
        return {type: "Buffer", data: Array.prototype.slice.call(this._arr || this, 0)};
      };
      var Z = 4096;
      n.prototype.slice = function(e2, t3) {
        var r2 = this.length;
        e2 = ~~e2, t3 = void 0 === t3 ? r2 : ~~t3, e2 < 0 ? (e2 += r2) < 0 && (e2 = 0) : e2 > r2 && (e2 = r2), t3 < 0 ? (t3 += r2) < 0 && (t3 = 0) : t3 > r2 && (t3 = r2), t3 < e2 && (t3 = e2);
        var i2;
        if (n.TYPED_ARRAY_SUPPORT)
          i2 = this.subarray(e2, t3), i2.__proto__ = n.prototype;
        else {
          var o2 = t3 - e2;
          i2 = new n(o2, void 0);
          for (var s2 = 0; s2 < o2; ++s2)
            i2[s2] = this[s2 + e2];
        }
        return i2;
      }, n.prototype.readUIntLE = function(e2, t3, r2) {
        e2 |= 0, t3 |= 0, r2 || O(e2, t3, this.length);
        for (var n2 = this[e2], i2 = 1, o2 = 0; ++o2 < t3 && (i2 *= 256); )
          n2 += this[e2 + o2] * i2;
        return n2;
      }, n.prototype.readUIntBE = function(e2, t3, r2) {
        e2 |= 0, t3 |= 0, r2 || O(e2, t3, this.length);
        for (var n2 = this[e2 + --t3], i2 = 1; t3 > 0 && (i2 *= 256); )
          n2 += this[e2 + --t3] * i2;
        return n2;
      }, n.prototype.readUInt8 = function(e2, t3) {
        return t3 || O(e2, 1, this.length), this[e2];
      }, n.prototype.readUInt16LE = function(e2, t3) {
        return t3 || O(e2, 2, this.length), this[e2] | this[e2 + 1] << 8;
      }, n.prototype.readUInt16BE = function(e2, t3) {
        return t3 || O(e2, 2, this.length), this[e2] << 8 | this[e2 + 1];
      }, n.prototype.readUInt32LE = function(e2, t3) {
        return t3 || O(e2, 4, this.length), (this[e2] | this[e2 + 1] << 8 | this[e2 + 2] << 16) + 16777216 * this[e2 + 3];
      }, n.prototype.readUInt32BE = function(e2, t3) {
        return t3 || O(e2, 4, this.length), 16777216 * this[e2] + (this[e2 + 1] << 16 | this[e2 + 2] << 8 | this[e2 + 3]);
      }, n.prototype.readIntLE = function(e2, t3, r2) {
        e2 |= 0, t3 |= 0, r2 || O(e2, t3, this.length);
        for (var n2 = this[e2], i2 = 1, o2 = 0; ++o2 < t3 && (i2 *= 256); )
          n2 += this[e2 + o2] * i2;
        return i2 *= 128, n2 >= i2 && (n2 -= Math.pow(2, 8 * t3)), n2;
      }, n.prototype.readIntBE = function(e2, t3, r2) {
        e2 |= 0, t3 |= 0, r2 || O(e2, t3, this.length);
        for (var n2 = t3, i2 = 1, o2 = this[e2 + --n2]; n2 > 0 && (i2 *= 256); )
          o2 += this[e2 + --n2] * i2;
        return i2 *= 128, o2 >= i2 && (o2 -= Math.pow(2, 8 * t3)), o2;
      }, n.prototype.readInt8 = function(e2, t3) {
        return t3 || O(e2, 1, this.length), 128 & this[e2] ? -1 * (255 - this[e2] + 1) : this[e2];
      }, n.prototype.readInt16LE = function(e2, t3) {
        t3 || O(e2, 2, this.length);
        var r2 = this[e2] | this[e2 + 1] << 8;
        return 32768 & r2 ? 4294901760 | r2 : r2;
      }, n.prototype.readInt16BE = function(e2, t3) {
        t3 || O(e2, 2, this.length);
        var r2 = this[e2 + 1] | this[e2] << 8;
        return 32768 & r2 ? 4294901760 | r2 : r2;
      }, n.prototype.readInt32LE = function(e2, t3) {
        return t3 || O(e2, 4, this.length), this[e2] | this[e2 + 1] << 8 | this[e2 + 2] << 16 | this[e2 + 3] << 24;
      }, n.prototype.readInt32BE = function(e2, t3) {
        return t3 || O(e2, 4, this.length), this[e2] << 24 | this[e2 + 1] << 16 | this[e2 + 2] << 8 | this[e2 + 3];
      }, n.prototype.readFloatLE = function(e2, t3) {
        return t3 || O(e2, 4, this.length), $.read(this, e2, true, 23, 4);
      }, n.prototype.readFloatBE = function(e2, t3) {
        return t3 || O(e2, 4, this.length), $.read(this, e2, false, 23, 4);
      }, n.prototype.readDoubleLE = function(e2, t3) {
        return t3 || O(e2, 8, this.length), $.read(this, e2, true, 52, 8);
      }, n.prototype.readDoubleBE = function(e2, t3) {
        return t3 || O(e2, 8, this.length), $.read(this, e2, false, 52, 8);
      }, n.prototype.writeUIntLE = function(e2, t3, r2, n2) {
        (e2 = +e2, t3 |= 0, r2 |= 0, !n2) && N(this, e2, t3, r2, Math.pow(2, 8 * r2) - 1, 0);
        var i2 = 1, o2 = 0;
        for (this[t3] = 255 & e2; ++o2 < r2 && (i2 *= 256); )
          this[t3 + o2] = e2 / i2 & 255;
        return t3 + r2;
      }, n.prototype.writeUIntBE = function(e2, t3, r2, n2) {
        (e2 = +e2, t3 |= 0, r2 |= 0, !n2) && N(this, e2, t3, r2, Math.pow(2, 8 * r2) - 1, 0);
        var i2 = r2 - 1, o2 = 1;
        for (this[t3 + i2] = 255 & e2; --i2 >= 0 && (o2 *= 256); )
          this[t3 + i2] = e2 / o2 & 255;
        return t3 + r2;
      }, n.prototype.writeUInt8 = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 1, 255, 0), n.TYPED_ARRAY_SUPPORT || (e2 = Math.floor(e2)), this[t3] = 255 & e2, t3 + 1;
      }, n.prototype.writeUInt16LE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 2, 65535, 0), n.TYPED_ARRAY_SUPPORT ? (this[t3] = 255 & e2, this[t3 + 1] = e2 >>> 8) : U(this, e2, t3, true), t3 + 2;
      }, n.prototype.writeUInt16BE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 2, 65535, 0), n.TYPED_ARRAY_SUPPORT ? (this[t3] = e2 >>> 8, this[t3 + 1] = 255 & e2) : U(this, e2, t3, false), t3 + 2;
      }, n.prototype.writeUInt32LE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 4, 4294967295, 0), n.TYPED_ARRAY_SUPPORT ? (this[t3 + 3] = e2 >>> 24, this[t3 + 2] = e2 >>> 16, this[t3 + 1] = e2 >>> 8, this[t3] = 255 & e2) : D(this, e2, t3, true), t3 + 4;
      }, n.prototype.writeUInt32BE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 4, 4294967295, 0), n.TYPED_ARRAY_SUPPORT ? (this[t3] = e2 >>> 24, this[t3 + 1] = e2 >>> 16, this[t3 + 2] = e2 >>> 8, this[t3 + 3] = 255 & e2) : D(this, e2, t3, false), t3 + 4;
      }, n.prototype.writeIntLE = function(e2, t3, r2, n2) {
        if (e2 = +e2, t3 |= 0, !n2) {
          var i2 = Math.pow(2, 8 * r2 - 1);
          N(this, e2, t3, r2, i2 - 1, -i2);
        }
        var o2 = 0, s2 = 1, a2 = 0;
        for (this[t3] = 255 & e2; ++o2 < r2 && (s2 *= 256); )
          e2 < 0 && 0 === a2 && 0 !== this[t3 + o2 - 1] && (a2 = 1), this[t3 + o2] = (e2 / s2 >> 0) - a2 & 255;
        return t3 + r2;
      }, n.prototype.writeIntBE = function(e2, t3, r2, n2) {
        if (e2 = +e2, t3 |= 0, !n2) {
          var i2 = Math.pow(2, 8 * r2 - 1);
          N(this, e2, t3, r2, i2 - 1, -i2);
        }
        var o2 = r2 - 1, s2 = 1, a2 = 0;
        for (this[t3 + o2] = 255 & e2; --o2 >= 0 && (s2 *= 256); )
          e2 < 0 && 0 === a2 && 0 !== this[t3 + o2 + 1] && (a2 = 1), this[t3 + o2] = (e2 / s2 >> 0) - a2 & 255;
        return t3 + r2;
      }, n.prototype.writeInt8 = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 1, 127, -128), n.TYPED_ARRAY_SUPPORT || (e2 = Math.floor(e2)), e2 < 0 && (e2 = 255 + e2 + 1), this[t3] = 255 & e2, t3 + 1;
      }, n.prototype.writeInt16LE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 2, 32767, -32768), n.TYPED_ARRAY_SUPPORT ? (this[t3] = 255 & e2, this[t3 + 1] = e2 >>> 8) : U(this, e2, t3, true), t3 + 2;
      }, n.prototype.writeInt16BE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 2, 32767, -32768), n.TYPED_ARRAY_SUPPORT ? (this[t3] = e2 >>> 8, this[t3 + 1] = 255 & e2) : U(this, e2, t3, false), t3 + 2;
      }, n.prototype.writeInt32LE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 4, 2147483647, -2147483648), n.TYPED_ARRAY_SUPPORT ? (this[t3] = 255 & e2, this[t3 + 1] = e2 >>> 8, this[t3 + 2] = e2 >>> 16, this[t3 + 3] = e2 >>> 24) : D(this, e2, t3, true), t3 + 4;
      }, n.prototype.writeInt32BE = function(e2, t3, r2) {
        return e2 = +e2, t3 |= 0, r2 || N(this, e2, t3, 4, 2147483647, -2147483648), e2 < 0 && (e2 = 4294967295 + e2 + 1), n.TYPED_ARRAY_SUPPORT ? (this[t3] = e2 >>> 24, this[t3 + 1] = e2 >>> 16, this[t3 + 2] = e2 >>> 8, this[t3 + 3] = 255 & e2) : D(this, e2, t3, false), t3 + 4;
      }, n.prototype.writeFloatLE = function(e2, t3, r2) {
        return j(this, e2, t3, true, r2);
      }, n.prototype.writeFloatBE = function(e2, t3, r2) {
        return j(this, e2, t3, false, r2);
      }, n.prototype.writeDoubleLE = function(e2, t3, r2) {
        return B(this, e2, t3, true, r2);
      }, n.prototype.writeDoubleBE = function(e2, t3, r2) {
        return B(this, e2, t3, false, r2);
      }, n.prototype.copy = function(e2, t3, r2, i2) {
        if (r2 || (r2 = 0), i2 || 0 === i2 || (i2 = this.length), t3 >= e2.length && (t3 = e2.length), t3 || (t3 = 0), i2 > 0 && i2 < r2 && (i2 = r2), i2 === r2)
          return 0;
        if (0 === e2.length || 0 === this.length)
          return 0;
        if (t3 < 0)
          throw new RangeError("targetStart out of bounds");
        if (r2 < 0 || r2 >= this.length)
          throw new RangeError("sourceStart out of bounds");
        if (i2 < 0)
          throw new RangeError("sourceEnd out of bounds");
        i2 > this.length && (i2 = this.length), e2.length - t3 < i2 - r2 && (i2 = e2.length - t3 + r2);
        var o2, s2 = i2 - r2;
        if (this === e2 && r2 < t3 && t3 < i2)
          for (o2 = s2 - 1; o2 >= 0; --o2)
            e2[o2 + t3] = this[o2 + r2];
        else if (s2 < 1e3 || !n.TYPED_ARRAY_SUPPORT)
          for (o2 = 0; o2 < s2; ++o2)
            e2[o2 + t3] = this[o2 + r2];
        else
          Uint8Array.prototype.set.call(e2, this.subarray(r2, r2 + s2), t3);
        return s2;
      }, n.prototype.fill = function(e2, t3, r2, i2) {
        if ("string" == typeof e2) {
          if ("string" == typeof t3 ? (i2 = t3, t3 = 0, r2 = this.length) : "string" == typeof r2 && (i2 = r2, r2 = this.length), 1 === e2.length) {
            var o2 = e2.charCodeAt(0);
            o2 < 256 && (e2 = o2);
          }
          if (void 0 !== i2 && "string" != typeof i2)
            throw new TypeError("encoding must be a string");
          if ("string" == typeof i2 && !n.isEncoding(i2))
            throw new TypeError("Unknown encoding: " + i2);
        } else
          "number" == typeof e2 && (e2 &= 255);
        if (t3 < 0 || this.length < t3 || this.length < r2)
          throw new RangeError("Out of range index");
        if (r2 <= t3)
          return this;
        t3 >>>= 0, r2 = void 0 === r2 ? this.length : r2 >>> 0, e2 || (e2 = 0);
        var s2;
        if ("number" == typeof e2)
          for (s2 = t3; s2 < r2; ++s2)
            this[s2] = e2;
        else {
          var a2 = n.isBuffer(e2) ? e2 : V(new n(e2, i2).toString()), u2 = a2.length;
          for (s2 = 0; s2 < r2 - t3; ++s2)
            this[s2 + t3] = a2[s2 % u2];
        }
        return this;
      };
      var ee = /[^+\/0-9A-Za-z-_]/g;
    }).call(this, "undefined" != typeof window ? window : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {}, e("buffer").Buffer);
  }, {"base64-js": 1, buffer: 3, ieee754: 5, isarray: 6}], 6: [function(e, t, r) {
    var n = {}.toString;
    t.exports = Array.isArray || function(e2) {
      return "[object Array]" == n.call(e2);
    };
  }, {}], 5: [function(e, t, r) {
    r.read = function(e2, t2, r2, n, i) {
      var o, s, a = 8 * i - n - 1, u = (1 << a) - 1, c = u >> 1, l = -7, h = r2 ? i - 1 : 0, p = r2 ? -1 : 1, f = e2[t2 + h];
      for (h += p, o = f & (1 << -l) - 1, f >>= -l, l += a; l > 0; o = 256 * o + e2[t2 + h], h += p, l -= 8)
        ;
      for (s = o & (1 << -l) - 1, o >>= -l, l += n; l > 0; s = 256 * s + e2[t2 + h], h += p, l -= 8)
        ;
      if (0 === o)
        o = 1 - c;
      else {
        if (o === u)
          return s ? NaN : 1 / 0 * (f ? -1 : 1);
        s += Math.pow(2, n), o -= c;
      }
      return (f ? -1 : 1) * s * Math.pow(2, o - n);
    }, r.write = function(e2, t2, r2, n, i, o) {
      var s, a, u, c = 8 * o - i - 1, l = (1 << c) - 1, h = l >> 1, p = 23 === i ? Math.pow(2, -24) - Math.pow(2, -77) : 0, f = n ? 0 : o - 1, d = n ? 1 : -1, m = t2 < 0 || 0 === t2 && 1 / t2 < 0 ? 1 : 0;
      for (t2 = Math.abs(t2), isNaN(t2) || t2 === 1 / 0 ? (a = isNaN(t2) ? 1 : 0, s = l) : (s = Math.floor(Math.log(t2) / Math.LN2), t2 * (u = Math.pow(2, -s)) < 1 && (s--, u *= 2), t2 += s + h >= 1 ? p / u : p * Math.pow(2, 1 - h), t2 * u >= 2 && (s++, u /= 2), s + h >= l ? (a = 0, s = l) : s + h >= 1 ? (a = (t2 * u - 1) * Math.pow(2, i), s += h) : (a = t2 * Math.pow(2, h - 1) * Math.pow(2, i), s = 0)); i >= 8; e2[r2 + f] = 255 & a, f += d, a /= 256, i -= 8)
        ;
      for (s = s << i | a, c += i; c > 0; e2[r2 + f] = 255 & s, f += d, s /= 256, c -= 8)
        ;
      e2[r2 + f - d] |= 128 * m;
    };
  }, {}], 1: [function(e, t, r) {
    "use strict";
    function n(e2) {
      var t2 = e2.length;
      if (t2 % 4 > 0)
        throw new Error("Invalid string. Length must be a multiple of 4");
      var r2 = e2.indexOf("=");
      return -1 === r2 && (r2 = t2), [r2, r2 === t2 ? 0 : 4 - r2 % 4];
    }
    function i(e2) {
      var t2 = n(e2), r2 = t2[0], i2 = t2[1];
      return 3 * (r2 + i2) / 4 - i2;
    }
    function o(e2, t2, r2) {
      return 3 * (t2 + r2) / 4 - r2;
    }
    function s(e2) {
      var t2, r2, i2 = n(e2), s2 = i2[0], a2 = i2[1], u2 = new p(o(e2, s2, a2)), c2 = 0, l2 = a2 > 0 ? s2 - 4 : s2;
      for (r2 = 0; r2 < l2; r2 += 4)
        t2 = h[e2.charCodeAt(r2)] << 18 | h[e2.charCodeAt(r2 + 1)] << 12 | h[e2.charCodeAt(r2 + 2)] << 6 | h[e2.charCodeAt(r2 + 3)], u2[c2++] = t2 >> 16 & 255, u2[c2++] = t2 >> 8 & 255, u2[c2++] = 255 & t2;
      return 2 === a2 && (t2 = h[e2.charCodeAt(r2)] << 2 | h[e2.charCodeAt(r2 + 1)] >> 4, u2[c2++] = 255 & t2), 1 === a2 && (t2 = h[e2.charCodeAt(r2)] << 10 | h[e2.charCodeAt(r2 + 1)] << 4 | h[e2.charCodeAt(r2 + 2)] >> 2, u2[c2++] = t2 >> 8 & 255, u2[c2++] = 255 & t2), u2;
    }
    function a(e2) {
      return l[e2 >> 18 & 63] + l[e2 >> 12 & 63] + l[e2 >> 6 & 63] + l[63 & e2];
    }
    function u(e2, t2, r2) {
      for (var n2, i2 = [], o2 = t2; o2 < r2; o2 += 3)
        n2 = (e2[o2] << 16 & 16711680) + (e2[o2 + 1] << 8 & 65280) + (255 & e2[o2 + 2]), i2.push(a(n2));
      return i2.join("");
    }
    function c(e2) {
      for (var t2, r2 = e2.length, n2 = r2 % 3, i2 = [], o2 = 0, s2 = r2 - n2; o2 < s2; o2 += 16383)
        i2.push(u(e2, o2, o2 + 16383 > s2 ? s2 : o2 + 16383));
      return 1 === n2 ? (t2 = e2[r2 - 1], i2.push(l[t2 >> 2] + l[t2 << 4 & 63] + "==")) : 2 === n2 && (t2 = (e2[r2 - 2] << 8) + e2[r2 - 1], i2.push(l[t2 >> 10] + l[t2 >> 4 & 63] + l[t2 << 2 & 63] + "=")), i2.join("");
    }
    r.byteLength = i, r.toByteArray = s, r.fromByteArray = c;
    for (var l = [], h = [], p = "undefined" != typeof Uint8Array ? Uint8Array : Array, f = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", d = 0, m = f.length; d < m; ++d)
      l[d] = f[d], h[f.charCodeAt(d)] = d;
    h["-".charCodeAt(0)] = 62, h["_".charCodeAt(0)] = 63;
  }, {}]}, {}, [28]);
  AWS.apiLoader.services.kinesis = {}, AWS.Kinesis = AWS.Service.defineService("kinesis", ["2013-12-02"]);
  AWS.apiLoader.services.kinesis["2013-12-02"] = {version: "2.0", metadata: {apiVersion: "2013-12-02", endpointPrefix: "kinesis", jsonVersion: "1.1", protocol: "json", protocolSettings: {h2: "eventstream"}, serviceAbbreviation: "Kinesis", serviceFullName: "Amazon Kinesis", serviceId: "Kinesis", signatureVersion: "v4", targetPrefix: "Kinesis_20131202", uid: "kinesis-2013-12-02"}, operations: {AddTagsToStream: {input: {type: "structure", required: ["StreamName", "Tags"], members: {StreamName: {}, Tags: {type: "map", key: {}, value: {}}}}}, CreateStream: {input: {type: "structure", required: ["StreamName", "ShardCount"], members: {StreamName: {}, ShardCount: {type: "integer"}}}}, DecreaseStreamRetentionPeriod: {input: {type: "structure", required: ["StreamName", "RetentionPeriodHours"], members: {StreamName: {}, RetentionPeriodHours: {type: "integer"}}}}, DeleteStream: {input: {type: "structure", required: ["StreamName"], members: {StreamName: {}, EnforceConsumerDeletion: {type: "boolean"}}}}, DeregisterStreamConsumer: {input: {type: "structure", members: {StreamARN: {}, ConsumerName: {}, ConsumerARN: {}}}}, DescribeLimits: {input: {type: "structure", members: {}}, output: {type: "structure", required: ["ShardLimit", "OpenShardCount"], members: {ShardLimit: {type: "integer"}, OpenShardCount: {type: "integer"}}}}, DescribeStream: {input: {type: "structure", required: ["StreamName"], members: {StreamName: {}, Limit: {type: "integer"}, ExclusiveStartShardId: {}}}, output: {type: "structure", required: ["StreamDescription"], members: {StreamDescription: {type: "structure", required: ["StreamName", "StreamARN", "StreamStatus", "Shards", "HasMoreShards", "RetentionPeriodHours", "StreamCreationTimestamp", "EnhancedMonitoring"], members: {StreamName: {}, StreamARN: {}, StreamStatus: {}, Shards: {shape: "Sp"}, HasMoreShards: {type: "boolean"}, RetentionPeriodHours: {type: "integer"}, StreamCreationTimestamp: {type: "timestamp"}, EnhancedMonitoring: {shape: "Sw"}, EncryptionType: {}, KeyId: {}}}}}}, DescribeStreamConsumer: {input: {type: "structure", members: {StreamARN: {}, ConsumerName: {}, ConsumerARN: {}}}, output: {type: "structure", required: ["ConsumerDescription"], members: {ConsumerDescription: {type: "structure", required: ["ConsumerName", "ConsumerARN", "ConsumerStatus", "ConsumerCreationTimestamp", "StreamARN"], members: {ConsumerName: {}, ConsumerARN: {}, ConsumerStatus: {}, ConsumerCreationTimestamp: {type: "timestamp"}, StreamARN: {}}}}}}, DescribeStreamSummary: {input: {type: "structure", required: ["StreamName"], members: {StreamName: {}}}, output: {type: "structure", required: ["StreamDescriptionSummary"], members: {StreamDescriptionSummary: {type: "structure", required: ["StreamName", "StreamARN", "StreamStatus", "RetentionPeriodHours", "StreamCreationTimestamp", "EnhancedMonitoring", "OpenShardCount"], members: {StreamName: {}, StreamARN: {}, StreamStatus: {}, RetentionPeriodHours: {type: "integer"}, StreamCreationTimestamp: {type: "timestamp"}, EnhancedMonitoring: {shape: "Sw"}, EncryptionType: {}, KeyId: {}, OpenShardCount: {type: "integer"}, ConsumerCount: {type: "integer"}}}}}}, DisableEnhancedMonitoring: {input: {type: "structure", required: ["StreamName", "ShardLevelMetrics"], members: {StreamName: {}, ShardLevelMetrics: {shape: "Sy"}}}, output: {shape: "S1b"}}, EnableEnhancedMonitoring: {input: {type: "structure", required: ["StreamName", "ShardLevelMetrics"], members: {StreamName: {}, ShardLevelMetrics: {shape: "Sy"}}}, output: {shape: "S1b"}}, GetRecords: {input: {type: "structure", required: ["ShardIterator"], members: {ShardIterator: {}, Limit: {type: "integer"}}}, output: {type: "structure", required: ["Records"], members: {Records: {type: "list", member: {type: "structure", required: ["SequenceNumber", "Data", "PartitionKey"], members: {SequenceNumber: {}, ApproximateArrivalTimestamp: {type: "timestamp"}, Data: {type: "blob"}, PartitionKey: {}, EncryptionType: {}}}}, NextShardIterator: {}, MillisBehindLatest: {type: "long"}}}}, GetShardIterator: {input: {type: "structure", required: ["StreamName", "ShardId", "ShardIteratorType"], members: {StreamName: {}, ShardId: {}, ShardIteratorType: {}, StartingSequenceNumber: {}, Timestamp: {type: "timestamp"}}}, output: {type: "structure", members: {ShardIterator: {}}}}, IncreaseStreamRetentionPeriod: {input: {type: "structure", required: ["StreamName", "RetentionPeriodHours"], members: {StreamName: {}, RetentionPeriodHours: {type: "integer"}}}}, ListShards: {input: {type: "structure", members: {StreamName: {}, NextToken: {}, ExclusiveStartShardId: {}, MaxResults: {type: "integer"}, StreamCreationTimestamp: {type: "timestamp"}}}, output: {type: "structure", members: {Shards: {shape: "Sp"}, NextToken: {}}}}, ListStreamConsumers: {input: {type: "structure", required: ["StreamARN"], members: {StreamARN: {}, NextToken: {}, MaxResults: {type: "integer"}, StreamCreationTimestamp: {type: "timestamp"}}}, output: {type: "structure", members: {Consumers: {type: "list", member: {shape: "S1y"}}, NextToken: {}}}}, ListStreams: {input: {type: "structure", members: {Limit: {type: "integer"}, ExclusiveStartStreamName: {}}}, output: {type: "structure", required: ["StreamNames", "HasMoreStreams"], members: {StreamNames: {type: "list", member: {}}, HasMoreStreams: {type: "boolean"}}}}, ListTagsForStream: {input: {type: "structure", required: ["StreamName"], members: {StreamName: {}, ExclusiveStartTagKey: {}, Limit: {type: "integer"}}}, output: {type: "structure", required: ["Tags", "HasMoreTags"], members: {Tags: {type: "list", member: {type: "structure", required: ["Key"], members: {Key: {}, Value: {}}}}, HasMoreTags: {type: "boolean"}}}}, MergeShards: {input: {type: "structure", required: ["StreamName", "ShardToMerge", "AdjacentShardToMerge"], members: {StreamName: {}, ShardToMerge: {}, AdjacentShardToMerge: {}}}}, PutRecord: {input: {type: "structure", required: ["StreamName", "Data", "PartitionKey"], members: {StreamName: {}, Data: {type: "blob"}, PartitionKey: {}, ExplicitHashKey: {}, SequenceNumberForOrdering: {}}}, output: {type: "structure", required: ["ShardId", "SequenceNumber"], members: {ShardId: {}, SequenceNumber: {}, EncryptionType: {}}}}, PutRecords: {input: {type: "structure", required: ["Records", "StreamName"], members: {Records: {type: "list", member: {type: "structure", required: ["Data", "PartitionKey"], members: {Data: {type: "blob"}, ExplicitHashKey: {}, PartitionKey: {}}}}, StreamName: {}}}, output: {type: "structure", required: ["Records"], members: {FailedRecordCount: {type: "integer"}, Records: {type: "list", member: {type: "structure", members: {SequenceNumber: {}, ShardId: {}, ErrorCode: {}, ErrorMessage: {}}}}, EncryptionType: {}}}}, RegisterStreamConsumer: {input: {type: "structure", required: ["StreamARN", "ConsumerName"], members: {StreamARN: {}, ConsumerName: {}}}, output: {type: "structure", required: ["Consumer"], members: {Consumer: {shape: "S1y"}}}}, RemoveTagsFromStream: {input: {type: "structure", required: ["StreamName", "TagKeys"], members: {StreamName: {}, TagKeys: {type: "list", member: {}}}}}, SplitShard: {input: {type: "structure", required: ["StreamName", "ShardToSplit", "NewStartingHashKey"], members: {StreamName: {}, ShardToSplit: {}, NewStartingHashKey: {}}}}, StartStreamEncryption: {input: {type: "structure", required: ["StreamName", "EncryptionType", "KeyId"], members: {StreamName: {}, EncryptionType: {}, KeyId: {}}}}, StopStreamEncryption: {input: {type: "structure", required: ["StreamName", "EncryptionType", "KeyId"], members: {StreamName: {}, EncryptionType: {}, KeyId: {}}}}, UpdateShardCount: {input: {type: "structure", required: ["StreamName", "TargetShardCount", "ScalingType"], members: {StreamName: {}, TargetShardCount: {type: "integer"}, ScalingType: {}}}, output: {type: "structure", members: {StreamName: {}, CurrentShardCount: {type: "integer"}, TargetShardCount: {type: "integer"}}}}}, shapes: {Sp: {type: "list", member: {type: "structure", required: ["ShardId", "HashKeyRange", "SequenceNumberRange"], members: {ShardId: {}, ParentShardId: {}, AdjacentParentShardId: {}, HashKeyRange: {type: "structure", required: ["StartingHashKey", "EndingHashKey"], members: {StartingHashKey: {}, EndingHashKey: {}}}, SequenceNumberRange: {type: "structure", required: ["StartingSequenceNumber"], members: {StartingSequenceNumber: {}, EndingSequenceNumber: {}}}}}}, Sw: {type: "list", member: {type: "structure", members: {ShardLevelMetrics: {shape: "Sy"}}}}, Sy: {type: "list", member: {}}, S1b: {type: "structure", members: {StreamName: {}, CurrentShardLevelMetrics: {shape: "Sy"}, DesiredShardLevelMetrics: {shape: "Sy"}}}, S1y: {type: "structure", required: ["ConsumerName", "ConsumerARN", "ConsumerStatus", "ConsumerCreationTimestamp"], members: {ConsumerName: {}, ConsumerARN: {}, ConsumerStatus: {}, ConsumerCreationTimestamp: {type: "timestamp"}}}}, paginators: {DescribeStream: {input_token: "ExclusiveStartShardId", limit_key: "Limit", more_results: "StreamDescription.HasMoreShards", output_token: "StreamDescription.Shards[-1].ShardId", result_key: "StreamDescription.Shards"}, ListStreamConsumers: {input_token: "NextToken", limit_key: "MaxResults", output_token: "NextToken"}, ListStreams: {input_token: "ExclusiveStartStreamName", limit_key: "Limit", more_results: "HasMoreStreams", output_token: "StreamNames[-1]", result_key: "StreamNames"}}, waiters: {StreamExists: {delay: 10, operation: "DescribeStream", maxAttempts: 18, acceptors: [{expected: "ACTIVE", matcher: "path", state: "success", argument: "StreamDescription.StreamStatus"}]}, StreamNotExists: {delay: 10, operation: "DescribeStream", maxAttempts: 18, acceptors: [{expected: "ResourceNotFoundException", matcher: "error", state: "success"}]}}};
  AWS.apiLoader.services.sts = {}, AWS.STS = AWS.Service.defineService("sts", ["2011-06-15"]), _xamzrequire = function e(n, i, t) {
    function r(s2, a) {
      if (!i[s2]) {
        if (!n[s2]) {
          var u = "function" == typeof _xamzrequire && _xamzrequire;
          if (!a && u)
            return u(s2, true);
          if (o)
            return o(s2, true);
          var c = new Error("Cannot find module '" + s2 + "'");
          throw c.code = "MODULE_NOT_FOUND", c;
        }
        var d = i[s2] = {exports: {}};
        n[s2][0].call(d.exports, function(e2) {
          var i2 = n[s2][1][e2];
          return r(i2 || e2);
        }, d, d.exports, e, n, i, t);
      }
      return i[s2].exports;
    }
    for (var o = "function" == typeof _xamzrequire && _xamzrequire, s = 0; s < t.length; s++)
      r(t[s]);
    return r;
  }({107: [function(e, n, i) {
    var t = e("../core"), r = e("../config_regional_endpoint");
    t.util.update(t.STS.prototype, {credentialsFrom: function(e2, n2) {
      return e2 ? (n2 || (n2 = new t.TemporaryCredentials()), n2.expired = false, n2.accessKeyId = e2.Credentials.AccessKeyId, n2.secretAccessKey = e2.Credentials.SecretAccessKey, n2.sessionToken = e2.Credentials.SessionToken, n2.expireTime = e2.Credentials.Expiration, n2) : null;
    }, assumeRoleWithWebIdentity: function(e2, n2) {
      return this.makeUnauthenticatedRequest("assumeRoleWithWebIdentity", e2, n2);
    }, assumeRoleWithSAML: function(e2, n2) {
      return this.makeUnauthenticatedRequest("assumeRoleWithSAML", e2, n2);
    }, setupRequestListeners: function(e2) {
      e2.addListener("validate", this.optInRegionalEndpoint, true);
    }, optInRegionalEndpoint: function(e2) {
      var n2 = e2.service, i2 = n2.config;
      if (i2.stsRegionalEndpoints = r(n2._originalConfig, {env: "AWS_STS_REGIONAL_ENDPOINTS", sharedConfig: "sts_regional_endpoints", clientConfig: "stsRegionalEndpoints"}), "regional" === i2.stsRegionalEndpoints && n2.isGlobalEndpoint) {
        if (!i2.region)
          throw t.util.error(new Error(), {code: "ConfigError", message: "Missing region in config"});
        var o = i2.endpoint.indexOf(".amazonaws.com"), s = i2.endpoint.substring(0, o) + "." + i2.region + i2.endpoint.substring(o);
        e2.httpRequest.updateEndpoint(s), e2.httpRequest.region = i2.region;
      }
    }});
  }, {"../config_regional_endpoint": 38, "../core": 39}]}, {}, [107]);
  AWS.apiLoader.services.sts["2011-06-15"] = {version: "2.0", metadata: {apiVersion: "2011-06-15", endpointPrefix: "sts", globalEndpoint: "sts.amazonaws.com", protocol: "query", serviceAbbreviation: "AWS STS", serviceFullName: "AWS Security Token Service", serviceId: "STS", signatureVersion: "v4", uid: "sts-2011-06-15", xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/"}, operations: {AssumeRole: {input: {type: "structure", required: ["RoleArn", "RoleSessionName"], members: {RoleArn: {}, RoleSessionName: {}, PolicyArns: {shape: "S4"}, Policy: {}, DurationSeconds: {type: "integer"}, Tags: {shape: "S8"}, TransitiveTagKeys: {type: "list", member: {}}, ExternalId: {}, SerialNumber: {}, TokenCode: {}}}, output: {resultWrapper: "AssumeRoleResult", type: "structure", members: {Credentials: {shape: "Sh"}, AssumedRoleUser: {shape: "Sm"}, PackedPolicySize: {type: "integer"}}}}, AssumeRoleWithSAML: {input: {type: "structure", required: ["RoleArn", "PrincipalArn", "SAMLAssertion"], members: {RoleArn: {}, PrincipalArn: {}, SAMLAssertion: {type: "string", sensitive: true}, PolicyArns: {shape: "S4"}, Policy: {}, DurationSeconds: {type: "integer"}}}, output: {resultWrapper: "AssumeRoleWithSAMLResult", type: "structure", members: {Credentials: {shape: "Sh"}, AssumedRoleUser: {shape: "Sm"}, PackedPolicySize: {type: "integer"}, Subject: {}, SubjectType: {}, Issuer: {}, Audience: {}, NameQualifier: {}}}}, AssumeRoleWithWebIdentity: {input: {type: "structure", required: ["RoleArn", "RoleSessionName", "WebIdentityToken"], members: {RoleArn: {}, RoleSessionName: {}, WebIdentityToken: {type: "string", sensitive: true}, ProviderId: {}, PolicyArns: {shape: "S4"}, Policy: {}, DurationSeconds: {type: "integer"}}}, output: {resultWrapper: "AssumeRoleWithWebIdentityResult", type: "structure", members: {Credentials: {shape: "Sh"}, SubjectFromWebIdentityToken: {}, AssumedRoleUser: {shape: "Sm"}, PackedPolicySize: {type: "integer"}, Provider: {}, Audience: {}}}}, DecodeAuthorizationMessage: {input: {type: "structure", required: ["EncodedMessage"], members: {EncodedMessage: {}}}, output: {resultWrapper: "DecodeAuthorizationMessageResult", type: "structure", members: {DecodedMessage: {}}}}, GetAccessKeyInfo: {input: {type: "structure", required: ["AccessKeyId"], members: {AccessKeyId: {}}}, output: {resultWrapper: "GetAccessKeyInfoResult", type: "structure", members: {Account: {}}}}, GetCallerIdentity: {input: {type: "structure", members: {}}, output: {resultWrapper: "GetCallerIdentityResult", type: "structure", members: {UserId: {}, Account: {}, Arn: {}}}}, GetFederationToken: {input: {type: "structure", required: ["Name"], members: {Name: {}, Policy: {}, PolicyArns: {shape: "S4"}, DurationSeconds: {type: "integer"}, Tags: {shape: "S8"}}}, output: {resultWrapper: "GetFederationTokenResult", type: "structure", members: {Credentials: {shape: "Sh"}, FederatedUser: {type: "structure", required: ["FederatedUserId", "Arn"], members: {FederatedUserId: {}, Arn: {}}}, PackedPolicySize: {type: "integer"}}}}, GetSessionToken: {input: {type: "structure", members: {DurationSeconds: {type: "integer"}, SerialNumber: {}, TokenCode: {}}}, output: {resultWrapper: "GetSessionTokenResult", type: "structure", members: {Credentials: {shape: "Sh"}}}}}, shapes: {S4: {type: "list", member: {type: "structure", members: {arn: {}}}}, S8: {type: "list", member: {type: "structure", required: ["Key", "Value"], members: {Key: {}, Value: {}}}}, Sh: {type: "structure", required: ["AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"], members: {AccessKeyId: {}, SecretAccessKey: {}, SessionToken: {}, Expiration: {type: "timestamp"}}}, Sm: {type: "structure", required: ["AssumedRoleId", "Arn"], members: {AssumedRoleId: {}, Arn: {}}}}, paginators: {}};

  // templates/jssdk/delytics.ts
  const AWS2 = window.AWS, awsConfig = {
    region: "us-east-1",
    accessKeyId: "AKIAUNYU4WHIQYNX6O7L",
    secretAccessKey: "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"
  };
  AWS2.config.update(awsConfig);
  const kinesis = new AWS2.Kinesis();
  window.delytics = {
    sendEvent(obj) {
      return __async(this, [], function* () {
        return yield kinesis.putRecord({
          StreamName: "dacastanalyticsInputDataStream",
          Data: JSON.stringify(obj),
          PartitionKey: Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
        }).promise();
      });
    }
  };
})();
