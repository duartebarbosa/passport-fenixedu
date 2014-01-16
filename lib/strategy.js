var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The FenixEdu authentication strategy authenticates requests by delegating to
 * FenixEdu using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientId`      	your FenixEdu application's client id
 *   - `clientSecret`  	your FenixEdu application's client secret
 *   - `callbackURL`   	URL to which FenixEdu will redirect the user after granting authorization (optional of set in your FenixEdu Application
 *   - `grant_type`		  Must be authorization_code
 *
 * Examples:
 *
 *     passport.use(new FenixEdu({
 *         client_id: '123-456-789',
 *         client_secret: 'shhh-its-a-secret'
 *         redirect_uri: 'https://www.example.net/auth/fenix/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
	options = options || {};
	options.authorizationURL = options.authorizationURL || 'https://fenix.tecnico.ulisboa.pt/oauth/userdialog';
	options.tokenURL = options.tokenURL || 'https://fenix.tecnico.ulisboa.pt/oauth/access_token';
  options.grant_type = options.grant_type || 'authorization_code';
	options.code = options.code || '';

	OAuth2Strategy.call(this, options, verify);
	this.name = 'fenixedu';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from FenixEdu.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `fenixedu`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get('https://fenix.tecnico.ulisboa.pt/api/fenix/v1/person', accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'fenixedu' };
      profile.id = json.istId;
      profile.username = json.name;
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
