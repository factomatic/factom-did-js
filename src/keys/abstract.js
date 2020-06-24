const { ECDSASecp256k1Key } = require('./ecdsa'),
    { Ed25519Key } = require('./eddsa'),
    { ENTRY_SCHEMA_V100 } = require('../constants'),
    { KeyType } = require('../enums'),
    { RSAKey } = require('./rsa'),
    {
        isValidDIDId,
        validateAlias,
        validateKeyType,
        validatePriorityRequirement
    } = require('../validators');

/**
 * Class representing the common fields and functionality in a ManagementKey and a DIDKey.
 * @param {string} alias - A human-readable nickname for the key.
 * @property {KeyType} keyType - Identifies the type of signature that the key pair can be used to generate and verify.
 * @property {string} controller - An entity that controls the key.
 * @property {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have
 *   in order to remove this key.
 * @property {string | Buffer} [publicKey] - A public key.
 * @property {string | Buffer} [privateKey] - A private key.
 */
class AbstractDIDKey {
    constructor(alias, keyType, controller, priorityRequirement, publicKey, privateKey) {
        this._validateInputParams(alias, keyType, controller, priorityRequirement);

        this.alias = alias;
        this.keyType = keyType;
        this.controller = controller;
        this.priorityRequirement = priorityRequirement;

        if (this.keyType == KeyType.EdDSA) {
            this.underlyingKey = new Ed25519Key(publicKey, privateKey);
        } else if (this.keyType == KeyType.ECDSA) {
            this.underlyingKey = new ECDSASecp256k1Key(publicKey, privateKey);
        } else {
            this.underlyingKey = new RSAKey(publicKey, privateKey);
        }
    }

    get publicKey() {
        return this.underlyingKey.publicKey;
    }

    get privateKey() {
        return this.underlyingKey.privateKey;
    }

    get verifyingKey() {
        return this.underlyingKey.verifyingKey;
    }

    get signingKey() {
        return this.underlyingKey.signingKey;
    }

    /**
     * Signs a message with the underlying private key. The message is hashed with SHA-256 before being signed.
     * @param {string | Buffer} message - The message to sign.
     * @returns {Uint8Array | Buffer} - The bytes of the signature.
     */
    sign(message) {
        return this.underlyingKey.sign(message);
    }

    /**
     * Verifies the signature of the given message.
     * @param {string | Buffer} message - The signed message.
     * @param {Buffer | Uint8Array} signature - The signature to verify.
     * @returns {boolean} - True if the signature is successfully verified, False otherwise.
     */
    verify(message, signature) {
        return this.underlyingKey.verify(message, signature);
    }

    /**
     * Builds an object suitable for recording on-chain.
     * @param {string} didId - The DID with which this key is associated. Note that this can be different from the key controller.
     * @param {string} version - The entry schema version
     * @returns {Object} An object with `id`, `type`, `controller` and an optional `priorityRequirement` properties. In addition to
     *   those, there is one extra property for the public key: if the selected signature type is SignatureType.RSA,
     *   then this property is called `publicKeyPem`, otherwise it is called `publicKeyBase58`.
     */
    /* istanbul ignore next */
    toEntryObj(didId, version = ENTRY_SCHEMA_V100) {
        if (version == ENTRY_SCHEMA_V100) {
            let entryObj = {
                id: this.fullId(didId),
                type: this.keyType,
                controller: this.controller,
                [this.underlyingKey.ON_CHAIN_PUB_KEY_NAME]: this.underlyingKey.publicKey
            };

            if (this.priorityRequirement !== undefined) {
                entryObj['priorityRequirement'] = this.priorityRequirement;
            }

            return entryObj;
        }

        throw new Error(`Unknown schema version: ${version}`);
    }

    /**
     * Generates new key pair for the key.
     */
    rotate() {
        if (!this.signingKey) {
            throw new Error('Private key must be set.');
        }

        this.underlyingKey = new this.underlyingKey.constructor();
    }

    /**
     * Constructs the full ID of the key.
     * @param {string} didId
     * @returns {string}
     */
    fullId(didId) {
        return `${didId}#${this.alias}`;
    }

    _validateInputParams(alias, keyType, controller, priorityRequirement) {
        validateAlias(alias);
        validateKeyType(keyType);

        if (!isValidDIDId(controller)) {
            throw new Error('Controller must be a valid DID Id.');
        }

        validatePriorityRequirement(priorityRequirement);
    }
}

module.exports = {
    AbstractDIDKey
};
