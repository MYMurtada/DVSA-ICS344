/**
 * Lesson 2 — Broken Authentication Fix
 * Secure JWT verification using Cognito's public JWKS endpoint.
 *
 * Problem pattern (never do this):
 *   const payload  = Buffer.from(token.split('.')[1], 'base64').toString();
 *   const identity = JSON.parse(payload);   // no signature check — trivially forgeable!
 *
 * Secure pattern (this file):
 *   const identity = await validateCognitoJwt(token, awsRegion, poolId);
 */

const https = require('https');
const jose  = require('node-jose');   // npm install node-jose

// Module-level cache — reused across warm Lambda invocations.
let _jwksCache = null;

/**
 * Fetch the JWKS from Cognito, returning a cached copy on subsequent calls.
 *
 * @param {string} region    AWS region (e.g. "us-east-1")
 * @param {string} poolId    Cognito User Pool ID
 * @returns {Promise<object>}
 */
async function _getJwks(region, poolId) {
    if (_jwksCache !== null) {
        return _jwksCache;
    }

    const jwksUrl = `https://cognito-idp.${region}.amazonaws.com/${poolId}/.well-known/jwks.json`;

    return new Promise((resolve, reject) => {
        https.get(jwksUrl, (res) => {
            let chunks = '';
            res.on('data',  (chunk) => { chunks += chunk; });
            res.on('end',   ()      => {
                try {
                    _jwksCache = JSON.parse(chunks);
                    resolve(_jwksCache);
                } catch (e) {
                    reject(new Error(`JWKS parse error: ${e.message}`));
                }
            });
            res.on('error', reject);
        }).on('error', reject);
    });
}

/**
 * Validate a Cognito access token and return its verified claims.
 * Throws an Error for any validation failure (bad sig, expired, wrong issuer, etc.).
 *
 * @param {string} token    Raw JWT string (no "Bearer " prefix)
 * @param {string} region   AWS region
 * @param {string} poolId   Cognito User Pool ID
 * @returns {Promise<object>} Verified claims object
 */
async function validateCognitoJwt(token, region, poolId) {
    const jwks     = await _getJwks(region, poolId);
    const keyStore = await jose.JWK.asKeyStore(jwks);

    let verificationResult;
    try {
        verificationResult = await jose.JWS.createVerify(keyStore).verify(token);
    } catch (sigError) {
        throw new Error(`JWT signature invalid: ${sigError.message}`);
    }

    const claims      = JSON.parse(verificationResult.payload.toString());
    const nowEpochSec = Math.floor(Date.now() / 1000);

    if (claims.exp <= nowEpochSec) {
        throw new Error('JWT has expired');
    }

    const expectedIss = `https://cognito-idp.${region}.amazonaws.com/${poolId}`;
    if (claims.iss !== expectedIss) {
        throw new Error(`JWT issuer mismatch — got: ${claims.iss}`);
    }

    if (claims.token_use !== 'access') {
        throw new Error(`Unexpected token_use value: ${claims.token_use}`);
    }

    return claims;
}

module.exports = { validateCognitoJwt };
