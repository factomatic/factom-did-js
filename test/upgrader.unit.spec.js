const { assert, expect } = require('chai').use(require('chai-bytes')),
    { createHash } = require('crypto'),
    { DID } = require('../src/did'),
    { DIDKey } = require('../src/keys/did'),
    { DID_METHOD_NAME, ENTRY_SCHEMA_V100 } = require('../src/constants'),
    { ManagementKey } = require('../src/keys/management'),
    { Network, EntryType, KeyType, DIDKeyPurpose } = require('../src/enums');

const didId = `${DID_METHOD_NAME}:${Network.Mainnet}:db4549470d24534fac28569d0f9c65b5ecef8d6332bc788b4d1b8dc1c2dae13a`;
const managementKeys = [
    new ManagementKey('my-first-mgmt-key', 0, KeyType.ECDSA, didId),
    new ManagementKey('my-second-mgmt-key', 1, KeyType.RSA, didId)
];
const didKeys = [new DIDKey('did-key-1', DIDKeyPurpose.AuthenticationKey, KeyType.EdDSA, didId)];

describe('Test DID Version Upgrader', function() {
    it('should throw error if you try to deactivate DID without management keys', function() {
        assert.throw(
            () => DID.builder().upgradeSpecVersion('0.3.0'),
            'Cannot upgrade method spec version for DID without management keys.'
        );
    });

    it('should throw error if new version is not an upgrade on old version', function() {
        const testCases = [undefined, '0.0.0', '0.1.0', '0.2'];
        testCases.forEach(version => {
            assert.throw(
                () =>
                    DID.builder(didId, [...managementKeys], [...didKeys]).upgradeSpecVersion(
                        version
                    ),
                'New version must be an upgrade on old version'
            );
        });
    });

    it('should export upgrade data correctly', function() {
        const newSpecVersion = '0.3.0';
        const did = DID.builder(didId, [...managementKeys], [...didKeys]);

        const entryData = did.upgradeSpecVersion(newSpecVersion).exportEntryData();

        const extIds = entryData['extIds'];
        assert.strictEqual(extIds.length, 4);
        expect(extIds[0]).to.equalBytes(Buffer.from(EntryType.VersionUpgrade));
        expect(extIds[1]).to.equalBytes(Buffer.from(ENTRY_SCHEMA_V100));

        const signingKey = did._managementKeys[0];
        const signingKeyId = signingKey.fullId(didId);
        const signedData = ''.concat(
            EntryType.VersionUpgrade,
            ENTRY_SCHEMA_V100,
            signingKeyId,
            entryData['content'].toString()
        );
        const sha256Hash = createHash('sha256');
        sha256Hash.update(Buffer.from(signedData));

        expect(extIds[2]).to.equalBytes(Buffer.from(signingKeyId));
        assert.isTrue(signingKey.verify(sha256Hash.digest(), extIds[3]));
        expect(entryData['content']).to.equalBytes(
            Buffer.from(JSON.stringify({ didMethodVersion: newSpecVersion }))
        );
    });
});
