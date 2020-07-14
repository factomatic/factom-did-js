import { assert } from 'chai';
import { DID, ManagementKey, KeyType } from '../../src/factom-did';
import { DID_METHOD_NAME } from '../../src/constants';

describe('Test Management Keys', function () {
    it('should add management keys', function () {
        const firstMgmtKeyAlias = 'management-key-1';
        const firstMgmtKeyPriority = 0;

        const secondMgmtKeyAlias = 'management-key-2';
        const secondMgmtKeyPriority = 1;
        const secondMgmtKeyType = KeyType.ECDSA;
        const secondMgmtKeyController = `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const secondMgmtKeyPriorityRequirement = 0;

        const thirdMgmtKeyAlias = 'management-key-3';
        const thirdMgmtKeyPriority = 2;
        const thirdMgmtKeyType = KeyType.RSA;

        const did = DID.builder()
            .managementKey(firstMgmtKeyAlias, firstMgmtKeyPriority)
            .managementKey(
                secondMgmtKeyAlias,
                secondMgmtKeyPriority,
                secondMgmtKeyType,
                secondMgmtKeyController,
                secondMgmtKeyPriorityRequirement
            )
            .managementKey(thirdMgmtKeyAlias, thirdMgmtKeyPriority, thirdMgmtKeyType)
            .build();

        const firstGeneratedMgmtKey = did.managementKeys[0];
        assert.strictEqual(firstGeneratedMgmtKey.alias, firstMgmtKeyAlias);
        assert.strictEqual(firstGeneratedMgmtKey.priority, firstMgmtKeyPriority);
        assert.strictEqual(firstGeneratedMgmtKey.keyType, KeyType.EdDSA);
        assert.strictEqual(firstGeneratedMgmtKey.controller, did.id);
        assert.isUndefined(firstGeneratedMgmtKey.priorityRequirement);
        assert.isString(firstGeneratedMgmtKey.publicKey);
        assert.isString(firstGeneratedMgmtKey.privateKey);
        assert.isDefined(firstGeneratedMgmtKey.verifyingKey);
        assert.isDefined(firstGeneratedMgmtKey.signingKey);

        const secondGeneratedMgmtKey = did.managementKeys[1];
        assert.strictEqual(secondGeneratedMgmtKey.alias, secondMgmtKeyAlias);
        assert.strictEqual(secondGeneratedMgmtKey.priority, secondMgmtKeyPriority);
        assert.strictEqual(secondGeneratedMgmtKey.keyType, secondMgmtKeyType);
        assert.strictEqual(secondGeneratedMgmtKey.controller, secondMgmtKeyController);
        assert.strictEqual(
            secondGeneratedMgmtKey.priorityRequirement,
            secondMgmtKeyPriorityRequirement
        );
        assert.isString(secondGeneratedMgmtKey.publicKey);
        assert.isString(secondGeneratedMgmtKey.privateKey);
        assert.isDefined(secondGeneratedMgmtKey.verifyingKey);
        assert.isDefined(secondGeneratedMgmtKey.signingKey);

        const thirdGeneratedMgmtKey = did.managementKeys[2];
        assert.strictEqual(thirdGeneratedMgmtKey.alias, thirdMgmtKeyAlias);
        assert.strictEqual(thirdGeneratedMgmtKey.priority, thirdMgmtKeyPriority);
        assert.strictEqual(thirdGeneratedMgmtKey.keyType, thirdMgmtKeyType);
        assert.strictEqual(thirdGeneratedMgmtKey.controller, did.id);
        assert.isUndefined(thirdGeneratedMgmtKey.priorityRequirement);
        assert.isString(thirdGeneratedMgmtKey.publicKey);
        assert.isString(thirdGeneratedMgmtKey.privateKey);
        assert.isDefined(thirdGeneratedMgmtKey.verifyingKey);
        assert.isDefined(thirdGeneratedMgmtKey.signingKey);

        assert.strictEqual(did.managementKeys.length, 3);
    });

    it('should throw error if alias is invalid', function () {
        const builder = DID.builder();
        const testCases = ['myManagementKey', 'my-m@nagement-key', 'my_management_key'];
        testCases.forEach((alias) => {
            assert.throw(
                () => builder.managementKey(alias, 0),
                'Alias must not be more than 32 characters long and must contain only lower-case letters, digits and hyphens.'
            );
        });
    });

    it('should throw error if priority is invalid', function () {
        const builder = DID.builder();
        const testCases = [-1, -2, 'one', 1.5];
        testCases.forEach((priority, index) => {
            assert.throw(
                () => builder.managementKey(`management-key-${index}`, priority as number),
                'Priority must be a non-negative integer.'
            );
        });
    });

    it('should throw error if alias is used', function () {
        const builder = DID.builder();
        const managementKeyAlias = 'management-key-1';
        builder.managementKey(managementKeyAlias, 0);
        assert.throw(
            () => builder.managementKey(managementKeyAlias, 0),
            `Duplicate alias "${managementKeyAlias}" detected.`
        );
    });

    it('should throw error if keyType is invalid', function () {
        const builder = DID.builder();
        const managementKeyAlias = 'management-key-1';
        const managementKeyType = 'invalidKeyType';
        assert.throw(
            () => builder.managementKey(managementKeyAlias, 0, managementKeyType as KeyType),
            'Type must be a valid signature type.'
        );
    });

    it('should throw error if controller is invalid', function () {
        const builder = DID.builder();
        const testCases = [
            `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654h05f838b8005`,
            'did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005',
            `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800`,
        ];
        testCases.forEach((controller, index) => {
            assert.throw(
                () =>
                    builder.managementKey(
                        `management-key-${index}`,
                        index,
                        KeyType.EdDSA,
                        controller
                    ),
                'Controller must be a valid DID Id.'
            );
        });
    });

    it('should throw error if priorityRequired is invalid', function () {
        const builder = DID.builder();
        const testCases = [-1, -2, 'one', 1.5];
        testCases.forEach((priorityRequirement, index) => {
            assert.throw(
                () =>
                    builder.managementKey(
                        `management-key-${index}`,
                        index,
                        undefined,
                        undefined,
                        priorityRequirement as number
                    ),
                'Priority requirement must be a non-negative integer.'
            );
        });
    });

    it('should throw error if entry schema version is invalid', function () {
        const didId = `${DID_METHOD_NAME}:db4549470d24534fac28569d0f9c65b5ecef8d6332bc788b4d1b8dc1c2dae13a`;
        const key = new ManagementKey('management-key-1', 0, KeyType.EdDSA, didId);
        const entrySchemaVersion = '1.1.0';
        assert.throw(
            () => key.toEntryObj(didId, entrySchemaVersion),
            `Unknown schema version: ${entrySchemaVersion}`
        );
    });
});
