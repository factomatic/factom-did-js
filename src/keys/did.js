const { AbstractDIDKey } = require('./abstract'),
  { DIDKeyPurpose } = require('../enums'),
  { ENTRY_SCHEMA_V100 } = require('../constants');

class DIDKey extends AbstractDIDKey {
  constructor (alias, purpose, keyType, controller, priorityRequirement) {
    super(alias, keyType, controller, priorityRequirement);

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