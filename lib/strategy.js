'use strict';

const jwkToPem = require('jwk-to-pem'),
  request = require('request-promise'),
  jwt = require('jsonwebtoken');

class CognitoExpress {
  constructor(config) {
    if (!config)
      throw new TypeError(
        'Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express'
      );

    if (configurationIsCorrect(config)) {
      this.userPoolId = config.cognitoUserPoolId;
      this.tokenUse = config.tokenUse;
      this.tokenExpiration = config.tokenExpiration || 3600000;
      this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this.userPoolId}`;
      this.promise = this.init((callback) => {});
    }
  }

  init(callback) {
    return Promise.resolve()
      .then(() => {
        this.pems = {};
        let keys = {
          keys: [
            {
              alg: 'RS256',
              e: 'AQAB',
              kid: 'Z1x0UVwZMPODrPFcIel8CzbItso9VlGpcbP3oJ/fmlg=',
              kty: 'RSA',
              n:
                'sIZ7dVFPsBUXPnkxj1JhaR9R9ztEDgXBWnvyxFq8Mio8OXqbCCCWOlWh147LQzaDvDHoROsujZxwl3MqYU-r594bEew_1jR2LTQobQwE7JeJB4t8F6_IiDtN_xNEw8uUYtCa6W7ukhi-NBVs2fA6GuetphJRAVJDjdOdcuOG0ZN_GrBk6oSewPf2yPzrC24SAr3xouM6q0_3iM0N8VgOvI9CIlS04E4-F0ll-CF8vNch2YRuAfliqdyBcDP-CKS24SPYZBoMzIB-FjSt25LZdnJbp70MMHMlCOi-onzfh-BArWWrGGVsOZHVUURpjnsaMl_DE3Cq9b_1LE0XFxalKw',
              use: 'sig',
            },
            {
              alg: 'RS256',
              e: 'AQAB',
              kid: '/gkc+pAvzJEHIztmp/nYnEpZlAn+R+Cs9oq6+Na9xcU=',
              kty: 'RSA',
              n:
                '3-jFRBZFBxoY5r07D6GaJMq-DU_GCZTtK2xwOqdMf50PjbfsSQOfh1WfWt7WZkKGICozxz-YZ0tfspCIuPOqzqJBksTRHAgmxQ28hbx6wGxs3UBxG96eCz_OLjdKitTXpYQYVM8Z6MddzVJSNglUXpkiqMME-jKSFFL7EI1tUNZzIxhB6qTDXxwRMd3H6bCBoFawXAOEoTr9g7sUfHEybkcpxXW7a2q_iY0kg0SZWBZShj7cxFgDT26qx3iFzZNjoRUmLVD6K8f4AqsdC4vOlVhAun8BAiw_0YOMKbgkF0qBhuEM-z6Fs27iGLXhAPEJS3vZ587om9TntthoE4LgmQ',
              use: 'sig',
            },
          ],
        }['keys'];
        for (let i = 0; i < keys.length; i++) {
          let key_id = keys[i].kid;
          let modulus = keys[i].n;
          let exponent = keys[i].e;
          let key_type = keys[i].kty;
          let jwk = { kty: key_type, n: modulus, e: exponent };
          let pem = jwkToPem(jwk);
          this.pems[key_id] = pem;
        }
        callback(true);
      })
      .catch((err) => {
        callback(false);
        throw new TypeError('Unable to generate certificate due to \n' + err);
      });
  }

  validate(token, callback) {
    const p = this.promise.then(() => {
      let decodedJwt = jwt.decode(token, { complete: true });

      if (!decodedJwt) return callback(`Not a valid JWT token`, null);

      if (decodedJwt.payload.iss !== this.iss)
        return callback(`token is not from your User Pool`, null);

      if (decodedJwt.payload.token_use !== this.tokenUse)
        return callback(`Not an ${this.tokenUse} token`, null);

      let kid = decodedJwt.header.kid;
      let pem = this.pems[kid];

      if (!pem) return callback(`Invalid ${this.tokenUse} token`, null);

      let params = {
        token: token,
        pem: pem,
        iss: this.iss,
        maxAge: this.tokenExpiration,
      };

      if (callback) {
        jwtVerify(params, callback);
      } else {
        return new Promise((resolve, reject) => {
          jwtVerify(params, (err, result) => {
            if (err) {
              reject(err);
            } else {
              resolve(result);
            }
          });
        });
      }
    });

    if (!callback) {
      return p;
    }
  }
}

function configurationIsCorrect(config) {
  let configurationPassed = false;
  switch (true) {
    case !config.region:
      throw new TypeError('AWS Region not specified in constructor');
      break;
    case !config.cognitoUserPoolId:
      throw new TypeError(
        'Cognito User Pool ID is not specified in constructor'
      );
      break;
    case !config.tokenUse:
      throw new TypeError(
        "Token use not specified in constructor. Possible values 'access' | 'id'"
      );
      break;
    case !(config.tokenUse == 'access' || config.tokenUse == 'id'):
      throw new TypeError(
        "Token use values not accurate in the constructor. Possible values 'access' | 'id'"
      );
      break;
    default:
      configurationPassed = true;
  }
  return configurationPassed;
}

function jwtVerify(params, callback) {
  jwt.verify(
    params.token,
    params.pem,
    {
      issuer: params.iss,
      maxAge: params.maxAge,
    },
    function (err, payload) {
      if (err) return callback(err, null);
      return callback(null, payload);
    }
  );
}

module.exports = CognitoExpress;
