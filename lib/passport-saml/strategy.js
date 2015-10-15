var passport = require('passport-strategy');
var util = require('util');
var saml = require('./saml');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
  this._passReqToCallback = !!options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  options.samlFallback = options.samlFallback || 'citrix-login-request';

  function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return self._saml.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
  }

  function redirectIfSuccess(err, url, body) {
    if (err) return self.error(err);

    var res = req.res;
    res.send(200, { location: url, SAMLRequest: body });
  }

  if (req.body && req.body.SAMLResponse) {
      this._saml.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
      this._saml.validatePostRequest(req.body, validateCallback);
  } else {
    var operation = {
      'citrix-login-request': 'getAuthorizePayload'
    }[options.samlFallback];
    if (!operation) {
      return self.fail();
    }
    this._saml[operation](req, redirectIfSuccess);
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert ) {
  return this._saml.generateServiceProviderMetadata( decryptionCert );
};

module.exports = Strategy;
