const { generateKeyPairSync } = require('crypto');

/**
 * Representation of an RSA key.
 */
class RSAKey {
  constructor() {
    this._generateNewKeyPair();
  }

  get ON_CHAIN_PUB_KEY_NAME() {
    return 'publicKeyPem';
  }

  _generateNewKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }
}

module.exports = {
  RSAKey
};