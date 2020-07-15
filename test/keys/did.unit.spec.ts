import { assert } from 'chai';
import { DID, KeyType, DIDKeyPurpose } from '../../src/factom-did';
import { DID_METHOD_NAME } from '../../src/constants';

describe('Test DID Keys', function() {
    it('should add DID keys', function() {
        const firstDIDKeyAlias = 'did-key-1';
        const firstDIDKeyPurpose = [DIDKeyPurpose.PublicKey];

        const secondDIDKeyAlias = 'did-key-2';
        const secondDIDKeyPurpose = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey];
        const secondDIDKeyType = KeyType.ECDSA;
        const secondDIDKeyController = `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const secondDIDKeyPriorityRequirement = 1;

        const thirdDIDKeyAlias = 'did-key-3';
        const thirdDIDKeyPurpose = DIDKeyPurpose.AuthenticationKey;
        const thirdDIDKeyType = KeyType.RSA;

        const did = DID.builder()
            .didKey(firstDIDKeyAlias, firstDIDKeyPurpose)
            .didKey(
                secondDIDKeyAlias,
                secondDIDKeyPurpose,
                secondDIDKeyType,
                secondDIDKeyController,
                secondDIDKeyPriorityRequirement
            )
            .didKey(thirdDIDKeyAlias, thirdDIDKeyPurpose, thirdDIDKeyType)
            .build();

        const firstGeneratedDIDKey = did.didKeys[0];
        assert.strictEqual(firstGeneratedDIDKey.alias, firstDIDKeyAlias);
        assert.strictEqual(firstGeneratedDIDKey.purpose, firstDIDKeyPurpose);
        assert.strictEqual(firstGeneratedDIDKey.keyType, KeyType.EdDSA);
        assert.strictEqual(firstGeneratedDIDKey.controller, did.id);
        assert.isUndefined(firstGeneratedDIDKey.priorityRequirement);
        assert.isString(firstGeneratedDIDKey.publicKey);
        assert.isString(firstGeneratedDIDKey.privateKey);

        const secondGeneratedDIDKey = did.didKeys[1];
        assert.strictEqual(secondGeneratedDIDKey.alias, secondDIDKeyAlias);
        assert.strictEqual(secondGeneratedDIDKey.purpose, secondDIDKeyPurpose);
        assert.strictEqual(secondGeneratedDIDKey.keyType, secondDIDKeyType);
        assert.strictEqual(secondGeneratedDIDKey.controller, secondDIDKeyController);
        assert.strictEqual(
            secondGeneratedDIDKey.priorityRequirement,
            secondDIDKeyPriorityRequirement
        );
        assert.isString(firstGeneratedDIDKey.publicKey);
        assert.isString(firstGeneratedDIDKey.privateKey);

        const thirdGeneratedDIDKey = did.didKeys[2];
        assert.strictEqual(thirdGeneratedDIDKey.alias, thirdDIDKeyAlias);
        assert.sameDeepMembers(thirdGeneratedDIDKey.purpose, [thirdDIDKeyPurpose]);
        assert.strictEqual(thirdGeneratedDIDKey.keyType, thirdDIDKeyType);
        assert.strictEqual(thirdGeneratedDIDKey.controller, did.id);
        assert.isUndefined(thirdGeneratedDIDKey.priorityRequirement);
        assert.isString(thirdGeneratedDIDKey.publicKey);
        assert.isString(thirdGeneratedDIDKey.privateKey);

        assert.strictEqual(did.didKeys.length, 3);
    });

    it('should throw error if alias is invalid', function() {
        const builder = DID.builder();
        const testCases = ['myDidKey', 'my-d!d-key', 'my_did_key'];
        testCases.forEach(alias => {
            assert.throw(
                () => builder.didKey(alias, DIDKeyPurpose.AuthenticationKey),
                'Alias must not be more than 32 characters long and must contain only lower-case letters, digits and hyphens.'
            );
        });
    });

    it('should throw error if purpose is invalid', function() {
        const builder = DID.builder();

        assert.throw(() => builder.didKey('did-key-1', 1 as any), 'Invalid purpose type.');

        assert.throw(
            () =>
                builder.didKey('did-key-1', [
                    DIDKeyPurpose.AuthenticationKey,
                    DIDKeyPurpose.AuthenticationKey
                ]),
            `Purpose must contain one or both of ${DIDKeyPurpose.PublicKey} and ${DIDKeyPurpose.AuthenticationKey} without repeated values`
        );

        assert.throw(
            () => builder.didKey('did-key-1', []),
            `Purpose must contain one or both of ${DIDKeyPurpose.PublicKey} and ${DIDKeyPurpose.AuthenticationKey} without repeated values`
        );

        assert.throw(
            () =>
                builder.didKey('did-key-1', [
                    DIDKeyPurpose.AuthenticationKey,
                    'invalid-purpose-type' as DIDKeyPurpose
                ]),
            'Purpose must contain only valid DIDKeyPurpose values.'
        );

        assert.throw(
            () => builder.didKey('did-key-1', 'invalid-purpose-type' as DIDKeyPurpose),
            'Purpose must contain only valid DIDKeyPurpose values.'
        );
    });

    it('should throw error if alias is used', function() {
        const builder = DID.builder();
        const didKeyAlias = 'did-key-1';
        builder.didKey(didKeyAlias, DIDKeyPurpose.PublicKey);
        assert.throw(
            () => builder.didKey(didKeyAlias, DIDKeyPurpose.AuthenticationKey),
            `Duplicate alias "${didKeyAlias}" detected.`
        );
    });

    it('should throw error if keyType is invalid', function() {
        const builder = DID.builder();
        const didKeyAlias = 'did-key-1';
        const didKeyType = 'invalidKeyType';
        assert.throw(
            () => builder.didKey(didKeyAlias, [DIDKeyPurpose.PublicKey], didKeyType as KeyType),
            'Type must be a valid signature type.'
        );
    });

    it('should throw error if controller is invalid', function() {
        const builder = DID.builder();
        const testCases = [
            `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654h05f838b8005`,
            'did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005',
            `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800`
        ];
        testCases.forEach((controller, index) => {
            assert.throw(
                () =>
                    builder.didKey(
                        `did-key-${index}`,
                        DIDKeyPurpose.PublicKey,
                        undefined,
                        controller
                    ),
                'Controller must be a valid DID Id.'
            );
        });
    });

    it('should throw error if priorityRequired is invalid', function() {
        const builder = DID.builder();
        const testCases = [-1, -2, 'one', 1.5];
        testCases.forEach((priorityRequirement, index) => {
            assert.throw(
                () =>
                    builder.didKey(
                        `did-key-${index}`,
                        DIDKeyPurpose.PublicKey,
                        undefined,
                        undefined,
                        priorityRequirement as number
                    ),
                'Priority requirement must be a non-negative integer.'
            );
        });
    });
});
