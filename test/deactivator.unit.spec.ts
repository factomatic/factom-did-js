import { assert, expect, use } from 'chai';
import chaibytes from 'chai-bytes';
import { createHash } from 'crypto';
import {
    DID,
    DIDKey,
    ManagementKey,
    Network,
    EntryType,
    KeyType,
    DIDKeyPurpose,
    Service,
} from '../src/factom-did';
import { DID_METHOD_NAME, ENTRY_SCHEMA_V100 } from '../src/constants';

use(chaibytes);

const didId = `${DID_METHOD_NAME}:${Network.Mainnet}:db4549470d24534fac28569d0f9c65b5ecef8d6332bc788b4d1b8dc1c2dae13a`;
const managementKeys = [
    new ManagementKey('my-first-mgmt-key', 0, KeyType.EdDSA, didId),
    new ManagementKey('my-second-mgmt-key', 1, KeyType.ECDSA, didId, 0),
];
const didKeys = [
    new DIDKey('did-key-1', DIDKeyPurpose.AuthenticationKey, KeyType.EdDSA, didId),
    new DIDKey(
        'did-key-2',
        [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey],
        KeyType.ECDSA,
        didId,
        1
    ),
];
const services = [new Service('gmail-service', 'EmailService', 'https://gmail.com', 2)];

describe('Test DID Deactivator', function () {
    it('should throw error if you try to deactivate DID without management keys', function () {
        assert.throw(
            () => DID.builder().deactivate(),
            'Cannot deactivate DID without a management key of priority 0.'
        );
    });

    it('should throw error if you try to deactivate DID without management key with priority 0', function () {
        assert.throw(
            () =>
                DID.builder(
                    didId,
                    [new ManagementKey('my-key', 1, KeyType.ECDSA, didId)],
                    [...didKeys]
                ).deactivate(),
            'Deactivation of a DID requires the availability of a management key with priority 0.'
        );
    });

    it('should export deactivation data correctly', function () {
        const did = DID.builder(didId, [...managementKeys], [...didKeys], [...services]);

        const entryData = did.deactivate().exportEntryData();

        const extIds = entryData['extIds'];
        assert.strictEqual(extIds.length, 4);
        expect(extIds[0]).to.equalBytes(Buffer.from(EntryType.Deactivation));
        expect(extIds[1]).to.equalBytes(Buffer.from(ENTRY_SCHEMA_V100));

        const signingKey = did.managementKeys[0];
        const signingKeyId = signingKey.fullId(didId);
        const signedData = ''.concat(EntryType.Deactivation, ENTRY_SCHEMA_V100, signingKeyId);
        const sha256Hash = createHash('sha256');
        sha256Hash.update(Buffer.from(signedData));

        expect(extIds[2]).to.equalBytes(Buffer.from(signingKeyId));
        assert.isTrue(signingKey.verify(sha256Hash.digest(), extIds[3]));
        expect(entryData['content']).to.equalBytes(Buffer.from(''));
    });
});
