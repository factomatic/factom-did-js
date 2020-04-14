const { AbstractDIDKey } = require('./abstract'),
  { DIDKeyPurpose } = require('../enums'),
  { ENTRY_SCHEMA_V100 } = require('../constants');

/**
 * Application-level key, which can be used for authentication, signing requests, encryption, decryption, etc.
 * @param {string} alias - A human-readable nickname for the key.
 * @param {DIDKeyPurpose | DIDKeyPurpose[]} purpose - Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
 * @property {KeyType} keyType - Identifies the type of signature that the key pair can be used to generate and verify.
 * @property {string} controller - An entity that controls the key.
 * @property {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have
 *   in order to remove this key.
 * @property {string | Buffer} [publicKey] - A public key.
 * @property {string | Buffer} [privateKey] - A private key.
 */
class DIDKey extends AbstractDIDKey {
  constructor (alias, purpose, keyType, controller, priorityRequirement, publicKey, privateKey) {
    super(alias, keyType, controller, priorityRequirement, publicKey, privateKey);

    let purposes;
    if (Array.isArray(purpose)) {
      purposes = purpose;
    } else if (typeof purpose == "string") {
      purposes = [purpose];
    } else {
      throw new Error('Invalid purpose type.')
    }

    if (new Set(purposes.values()).size !== purposes.length
      || ![1, 2].includes(purposes.length)) {
        throw new Error(`Purpose must contain one or both of ${DIDKeyPurpose.PublicKey} and ${DIDKeyPurpose.AuthenticationKey} without repeated values`);
    }

    purposes.forEach(purpose => {
      if (![DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey].includes(purpose)) {
        throw new Error('Purpose must contain only valid DIDKeyPurpose values.');
      }
    });

    this.purpose = purposes;
  }

  toEntryObj(didId, version=ENTRY_SCHEMA_V100) {
    let entryObj = super.toEntryObj(didId, version);
    entryObj['purpose'] = this.purpose;
    return entryObj;
  }
}

module.exports = {
  DIDKey
};