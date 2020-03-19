const { ECDSASecp256k1Key } = require('./ecdsa'), 
  { Ed25519Key } = require('./eddsa'),
  { ENTRY_SCHEMA_V100 } = require('../constants'),
  { KeyType } = require('../enums'),
  { RSAKey } = require('./rsa'),
  { validateAlias, validateKeyType, validateDIDId, validatePriorityRequirement } = require('../validators');

/**
 * Class representing the common fields and functionality in a ManagementKey and a DIDKey.
 * @param {string} alias - A human-readable nickname for the key.
 * @property {KeyType} keyType - Identifies the type of signature that the key pair can be used to generate and verify.
 * @property {string} controller - An entity that controls the key.
 * @property {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have
 *   in order to remove this key.
 */
class AbstractDIDKey {
  constructor (alias, keyType, controller, priorityRequirement) {
    this._validateInputParams(alias, keyType, controller, priorityRequirement);

    this.alias = alias;
    this.keyType = keyType;
    this.controller = controller;
    this.priorityRequirement = priorityRequirement;

    if (this.keyType == KeyType.EdDSA) {
      this.underlyingKey = new Ed25519Key();
    } else if (this.keyType == KeyType.ECDSA) {
      this.underlyingKey = new ECDSASecp256k1Key();
    } else if (this.keyType == KeyType.RSA) {
      this.underlyingKey = new RSAKey();
    } else {
      throw new Error(`Unsupported signature type: ${this.keyType}`);
    }
  }

  get publicKey() {
    return this.underlyingKey.publicKey;
  }

  get privateKey() {
    return this.underlyingKey.privateKey;
  }

  /**
   * Builds an object suitable for recording on-chain.
   * @param {string} didId - The DID with which this key is associated. Note that this can be different from the key controller.
   * @param {string} version - The entry schema version
   * @returns {Object} An object with `id`, `type`, `controller` and an optional `priorityRequirement` properties. In addition to
      those, there is one extra property for the public key: if the selected signature type is SignatureType.RSA,
      then this property is called `publicKeyPem`, otherwise it is called `publicKeyBase58`.
  */
  toEntryObj(didId, version=ENTRY_SCHEMA_V100) {
    if (version == ENTRY_SCHEMA_V100) {
      let entryObj = {
        id: this._fullId(didId),
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
   * Constructs the full ID of the key.
   * @param {string} didId
   * @returns {string}
  */
  _fullId(didId) {
    return `${didId}#${this.alias}`;
  }

  _validateInputParams(alias, keyType, controller, priorityRequirement) {
    validateAlias(alias);
    validateKeyType(keyType);
    validateDIDId(controller);
    validatePriorityRequirement(priorityRequirement);
  }
}

module.exports = {
  AbstractDIDKey
};