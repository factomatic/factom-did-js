import { assert } from 'chai';
import { decode } from 'bs58';
import { Ed25519Key } from '../../src/factom-did';

describe('Test EdDSA Keys', function () {
    it('should generate new key pair', function () {
        const key = new Ed25519Key();

        assert.isString(key.publicKey);
        assert.isString(key.privateKey);
        assert.strictEqual(key.verifyingKey.length, 32);
        assert.strictEqual((key.signingKey as Uint8Array).length, 64);
    });

    it('should initialize with base58 encoded public and private key', function () {
        const firstKey = new Ed25519Key();
        const secondKey = new Ed25519Key(firstKey.publicKey, firstKey.privateKey);

        assert.strictEqual(secondKey.publicKey, firstKey.publicKey);
        assert.strictEqual(secondKey.privateKey, firstKey.privateKey);
    });

    it('should initialize with public and private key as bytes', function () {
        const firstKey = new Ed25519Key();
        const secondKey = new Ed25519Key(
            decode(firstKey.publicKey),
            decode(firstKey.privateKey as string)
        );

        assert.strictEqual(secondKey.publicKey, firstKey.publicKey);
        assert.strictEqual(secondKey.privateKey, firstKey.privateKey);
    });

    it('should initialize only with private key', function () {
        const firstKey = new Ed25519Key();
        const secondKey = new Ed25519Key(undefined, decode(firstKey.privateKey as string));

        assert.strictEqual(secondKey.publicKey, firstKey.publicKey);
    });

    it('should initialize only with public key', function () {
        const firstKey = new Ed25519Key();
        const secondKey = new Ed25519Key(decode(firstKey.publicKey));

        assert.strictEqual(secondKey.publicKey, firstKey.publicKey);
        assert.isUndefined(secondKey.privateKey);
    });

    it('should throw error if public key is not string or Buffer', function () {
        const testCases = [1, {}];
        testCases.forEach((publicKey: any) => {
            assert.throw(() => new Ed25519Key(publicKey), 'Public key must be a string or Buffer.');
        });
    });

    it('should throw error if private key is not string or Buffer', function () {
        const testCases = [1, {}];
        testCases.forEach((privateKey: any) => {
            assert.throw(
                () => new Ed25519Key(undefined, privateKey),
                'Private key must be a string or Buffer.'
            );
        });
    });

    it('should throw error if the provided public key does not correspond to the private key', function () {
        const firstKey = new Ed25519Key();
        const secondKey = new Ed25519Key();

        assert.throw(
            () => new Ed25519Key(firstKey.publicKey, secondKey.privateKey),
            'The provided public key does not match the one derived from the provided private key.'
        );
    });

    it('should throw error if the provided public key is invalid', function () {
        const key = new Ed25519Key();

        assert.throw(
            () => new Ed25519Key(key.privateKey),
            'Invalid Ed25519 public key. Must be a 32-byte value.'
        );
    });

    it('should sign a message and verify the signature', function () {
        const key = new Ed25519Key();
        const message = 'test message';
        const testCases = [message, Buffer.from(message)];

        testCases.forEach((_message) => {
            const signature = key.sign(_message);
            const verified = key.verify(_message, signature);
            assert.isTrue(verified);
        });
    });

    it('should return false if the signature cannot be verified', function () {
        const signingKey = new Ed25519Key();
        const message = 'test message';
        const falseMessage = 'test messag';
        const signature = signingKey.sign(message);
        const verified = signingKey.verify(falseMessage, signature);

        assert.isFalse(verified);
    });

    it('should throw error if private key is not set', function () {
        const firstKey = new Ed25519Key();
        const signingKey = new Ed25519Key(firstKey.publicKey);
        const message = 'test message';

        assert.throw(() => signingKey.sign(message), 'Private key is not set.');
    });

    it('should throw error if signing message is not string or Buffer', function () {
        const signingKey = new Ed25519Key();
        const testCases = [{}, 5];

        testCases.forEach((message: any) => {
            assert.throw(() => signingKey.sign(message), 'Message must be a string or Buffer.');
        });
    });

    it('should throw error if verifying message is not string or Buffer', function () {
        const signingKey = new Ed25519Key();
        const testCases = [{}, 5];

        testCases.forEach((message: any) => {
            assert.throw(
                () => signingKey.verify(message, Buffer.from([])),
                'Message must be a string or Buffer.'
            );
        });
    });

    it('should throw error if signature is not Uint8Array or Buffer', function () {
        const signingKey = new Ed25519Key();
        const message = 'test message';

        assert.throw(
            () => signingKey.verify(message, 'invalid signature' as any),
            'unexpected type, use Uint8Array'
        );
    });
});
