const base58 = require('bs58'), 
  elliptic = require('elliptic');

/**
 * Representation of an ECDSASecp256k1 key.
 */
class ECDSASecp256k1Key {
  constructor() {
    this._generateNewKeyPair();
  }

  get ON_CHAIN_PUB_KEY_NAME() {
    return 'publicKeyBase58';
  }

  _generateNewKeyPair() {
    const ec = new elliptic.ec('secp256k1');
    const key = ec.genKeyPair();

    const compressedPubPoint = key.getPublic(true, 'hex');
    const privateKey = key.getPrivate('hex');

    this.publicKey = base58.encode(Buffer.from(compressedPubPoint, 'hex'));
    this.privateKey = base58.encode(Buffer.from(privateKey, 'hex'));
  }
}

module.exports = {
  ECDSASecp256k1Key
};