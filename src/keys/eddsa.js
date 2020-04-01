const base58 = require('bs58'), 
  nacl = require('tweetnacl/nacl-fast');

/**
 * Representation of an Ed25519 key.
 */
class Ed25519Key {
  constructor() {
    this._generateNewKeyPair();
  }

  get ON_CHAIN_PUB_KEY_NAME() {
    return 'publicKeyBase58';
  }

  _generateNewKeyPair() {
    const seed = nacl.randomBytes(32);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);

    this.publicKey = base58.encode(Buffer.from(keyPair.publicKey));
    this.privateKey = base58.encode(Buffer.from(keyPair.secretKey));
  }
}

module.exports = {
  Ed25519Key
};