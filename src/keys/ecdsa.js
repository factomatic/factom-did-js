const base58 = require('bs58'),
  { createHash } = require('crypto'),
  elliptic = require('elliptic');

/**
 * Representation of an ECDSASecp256k1 key. Instances of this class allow signing of messages and signature
 * verification, as well as key creation and derivation of a public key from a private key.
 * @param {string | Buffer} [publicKey] - An optional base58 encoded publicKey or Buffer.
 * @param {string | Buffer} [privateKey] - An optional base58 encoded privateKey or Buffer.
 */
class ECDSASecp256k1Key {
  constructor(publicKey, privateKey) {
    this.ec = new elliptic.ec('secp256k1');
    if (!publicKey && !privateKey) {
      this._generateNewKeyPair();
      return;
    }

    if (publicKey && typeof publicKey !== 'string' && !Buffer.isBuffer(publicKey)) {
      throw new Error('Public key must be a string or Buffer.');
    }

    if (privateKey && typeof privateKey !== 'string' && !Buffer.isBuffer(privateKey)) {
      throw new Error('Private key must be a string or Buffer.');
    }
    
    this._deriveSigningAndVerifyingKey(publicKey, privateKey);
  }

  get ON_CHAIN_PUB_KEY_NAME() {
    return 'publicKeyBase58';
  }

  get publicKey() {
    return base58.encode(this.verifyingKey);
  }

  get privateKey() {
    if (this.signingKey) {
      return base58.encode(this.signingKey);
    }
  }

  /**
  * Signs a message with the existing private key. The message is hashed with SHA-256 before being signed.
  * @param {string | Buffer} message - The message to sign.
  * @returns {Uint8Array} - The bytes of the signature.
  */
  sign(message) {
    if (!this.signingKey) {
      throw new Error('Private key is not set.');
    }

    if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
      throw new Error('Message must be a string or Buffer.');
    }

    const sha256Hash = createHash('sha256');
    sha256Hash.update(message);

    const key = this.ec.keyFromPrivate(this.signingKey);
    return key.sign(sha256Hash.digest()).toDER();
  }

  /**
  * Verifies the signature of the given message.
  * @param {string | Buffer} message - The signed message.
  * @param {Buffer | Uint8Array} signature - The signature to verify.
  * @returns {boolean} - True if the signature is successfully verified, False otherwise.
  */
  verify(message, signature) {
    if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
      throw new Error('Message must be a string or Buffer.');
    }

    const sha256Hash = createHash('sha256');
    sha256Hash.update(message);

    const key = this.ec.keyFromPrivate(this.signingKey);
    return key.verify(sha256Hash.digest(), signature);
  }

  _generateNewKeyPair() {
    const key = this.ec.genKeyPair();

    this.verifyingKey = Buffer.from(key.getPublic(true, 'hex'), 'hex');
    this.signingKey = Buffer.from(key.getPrivate('hex'), 'hex');
  }

  _deriveSigningAndVerifyingKey(publicKey, privateKey) {
    if (publicKey && typeof publicKey == 'string') {
      publicKey = base58.decode(publicKey);
    }

    if (privateKey) {
      if (typeof privateKey == 'string') {
        privateKey = base58.decode(privateKey);
      }

      const key = this.ec.keyFromPrivate(privateKey);
      const verifyingKey = Buffer.from(key.getPublic(true, 'hex'), 'hex');

      if (publicKey && Buffer.compare(verifyingKey, publicKey) !== 0) {
        throw new Error('The provided public key does not match the one derived from the provided private key.');
      }

      this.verifyingKey = verifyingKey;
      this.signingKey = Buffer.from(key.getPrivate('hex'), 'hex');
    } else {
      try {
        this.ec.keyFromPublic(publicKey);
        this.verifyingKey = publicKey;
      } catch {
        throw new Error('Invalid ECDSASecp256k1Key public key.');
      }
    }
  }
}

module.exports = {
  ECDSASecp256k1Key
};