const { createHash } = require('crypto'),
    { EntryType } = require('./enums'),
    { ENTRY_SCHEMA_V100 } = require('./constants');

/**
 * Facilitates the creation of a DIDMethodVersionUpgrade entry for an existing DID.
 * @param {DIDBuilder} didBuilder
 * @param {string} newSpecVersion - The new version to upgrade to.
 */
class DIDVersionUpgrader {
    constructor(didBuilder, newSpecVersion) {
        if (!newSpecVersion || parseFloat(newSpecVersion) <= parseFloat(didBuilder._specVersion)) {
            throw new Error('New version must be an upgrade on old version');
        }

        this.didBuilder = didBuilder;
        this.newSpecVersion = newSpecVersion;
    }

    exportEntryData() {
        const signingKey = this.didBuilder._managementKeys.sort(
            (a, b) => a.priority - b.priority
        )[0];
        const signingKeyId = signingKey.fullId(this.didBuilder._id);
        const entryContent = JSON.stringify({ didMethodVersion: this.newSpecVersion });
        const dataToSign = ''.concat(
            EntryType.VersionUpgrade,
            ENTRY_SCHEMA_V100,
            signingKeyId,
            entryContent
        );

        const sha256Hash = createHash('sha256');
        sha256Hash.update(Buffer.from(dataToSign));

        const signature = signingKey.sign(sha256Hash.digest());
        const extIds = [
            Buffer.from(EntryType.VersionUpgrade),
            Buffer.from(ENTRY_SCHEMA_V100),
            Buffer.from(signingKeyId),
            Buffer.from(signature)
        ];

        return { extIds, content: Buffer.from(entryContent) };
    }
}

module.exports = {
    DIDVersionUpgrader
};
