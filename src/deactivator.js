const { createHash } = require('crypto'),
  { EntryType } = require('./enums'),
  { ENTRY_SCHEMA_V100 } = require('./constants');

/**
 * Facilitates the creation of a DIDDeactivation entry.
 * @param {DIDBuilder} didBuilder - The DID to deactivate.
 */
class DIDDeactivator {
  constructor(didBuilder) {
    this.didBuilder = didBuilder;
    this.signingKey = this.didBuilder._managementKeys.sort((a, b) => a.priority - b.priority)[0];

    if (this.signingKey.priority !== 0) {
      throw new Error('Deactivation of a DID requires the availability of a management key with priority 0.');
    }
  }

  exportEntryData() {
    const signingKeyId = this.signingKey.fullId(this.didBuilder._id);
    const dataToSign = "".concat(EntryType.Deactivation, ENTRY_SCHEMA_V100, signingKeyId);

    const sha256Hash = createHash('sha256');
    sha256Hash.update(Buffer.from(dataToSign));

    const signature = this.signingKey.sign(sha256Hash.digest());
    const extIds = [
      Buffer.from(EntryType.Deactivation),
      Buffer.from(ENTRY_SCHEMA_V100),
      Buffer.from(signingKeyId),
      Buffer.from(signature)
    ];

    /** The content of the DIDDeactivation entry is empty */
    return {extIds, content: Buffer.from('')};
  }
}

module.exports = {
  DIDDeactivator
};