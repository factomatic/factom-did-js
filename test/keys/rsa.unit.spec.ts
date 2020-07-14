import { assert } from 'chai';
import { RSAKey } from '../../src/factom-did';

describe('Test RSA Keys', function () {
    it('should generate new key pair', function () {
        const key = new RSAKey();

        assert.isString(key.publicKey);
        assert.isString(key.privateKey);
        assert.isString(key.verifyingKey);
        assert.isString(key.signingKey);
    });

    it('should initialize with PEM encoded public and private key', function () {
        const firstKey = new RSAKey();
        const secondKey = new RSAKey(firstKey.publicKey, firstKey.privateKey);

        assert.strictEqual(secondKey.publicKey, firstKey.publicKey);
        assert.strictEqual(secondKey.privateKey, firstKey.privateKey);
    });

    it('should throw error if public key is not string', function () {
        const testCases = [1, {}];
        testCases.forEach((publicKey) => {
            assert.throw(() => new RSAKey(publicKey as string), 'Public key must be PEM encoded.');
        });
    });

    it('should throw error if private key is not string', function () {
        const testCases = [1, {}];
        testCases.forEach((privateKey) => {
            assert.throw(
                () => new RSAKey(undefined, privateKey as string),
                'Private key must be PEM encoded.'
            );
        });
    });

    it('should sign a message and verify the signature', function () {
        const key = new RSAKey();
        const message = 'test message';
        const testCases = [message, Buffer.from(message)];

        testCases.forEach((_message) => {
            const signature = key.sign(_message);
            const verified = key.verify(_message, signature);
            assert.isTrue(verified);
        });
    });

    it('should return false if the signature cannot be verified', function () {
        const signingKey = new RSAKey();
        const message = 'test message';
        const falseMessage = 'test messag';
        const signature = signingKey.sign(message);
        const verified = signingKey.verify(falseMessage, signature);

        assert.isFalse(verified);
    });

    it('should throw error if private key is not set', function () {
        const firstKey = new RSAKey();
        const signingKey = new RSAKey(firstKey.publicKey);
        const message = 'test message';

        assert.throw(() => signingKey.sign(message), 'Private key is not set.');
    });

    it('should throw error if public key is not set', function () {
        const firstKey = new RSAKey();
        const signingKey = new RSAKey(undefined, firstKey.privateKey);
        const message = 'test message';
        const signature = signingKey.sign(message);

        assert.throw(() => signingKey.verify(message, signature), 'Public key is not set.');
    });

    it('should throw error if signing message is not string or Buffer', function () {
        const signingKey = new RSAKey();
        const testCases = [{}, 5];

        testCases.forEach((message) => {
            assert.throw(
                () => signingKey.sign(message as string),
                'Message must be a string or Buffer.'
            );
        });
    });

    it('should throw error if verifying message is not string or Buffer', function () {
        const signingKey = new RSAKey();
        const testCases = [{}, 5];

        testCases.forEach((message) => {
            assert.throw(
                () => signingKey.verify(message as string, Buffer.from([])),
                'Message must be a string or Buffer.'
            );
        });
    });
});
