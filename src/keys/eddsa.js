const base58 = require('bs58'),
    { createHash } = require('crypto'),
    nacl = require('tweetnacl/nacl-fast');

/**
 * Representation of an Ed25519 key. Instances of this class allow signing of messages and signature verification, as
 * well as key creation and derivation of a public key from a private key.
 * @param {string | Buffer} publicKey - An optional base58 encoded publicKey or Buffer.
 * @param {string | Buffer} [privateKey] - An optional base58 encoded privateKey or Buffer.
 */
class Ed25519Key {
    constructor(publicKey, privateKey) {
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
        } else {
            return undefined;
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
        return nacl.sign.detached(sha256Hash.digest(), this.signingKey);
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
        return nacl.sign.detached.verify(sha256Hash.digest(), signature, this.verifyingKey);
    }

    _generateNewKeyPair() {
        const keyPair = nacl.sign.keyPair();

        this.verifyingKey = keyPair.publicKey;
        this.signingKey = keyPair.secretKey;
    }

    _deriveSigningAndVerifyingKey(publicKey, privateKey) {
        if (publicKey && typeof publicKey == 'string') {
            publicKey = base58.decode(publicKey);
        }

        if (privateKey) {
            if (typeof privateKey == 'string') {
                privateKey = base58.decode(privateKey);
            }

            const keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);

            if (publicKey && Buffer.compare(keyPair.publicKey, publicKey) !== 0) {
                throw new Error(
                    'The provided public key does not match the one derived from the provided private key.'
                );
            }

            this.verifyingKey = keyPair.publicKey;
            this.signingKey = keyPair.secretKey;
        } else {
            if (publicKey.length !== 32) {
                throw new Error('Invalid Ed25519 public key. Must be a 32-byte value.');
            }

            this.verifyingKey = publicKey;
        }
    }
}

module.exports = {
    Ed25519Key
};
