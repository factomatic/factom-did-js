import { createVerify, createSign, generateKeyPairSync } from 'crypto';

/**
 * Representation of an RSA key. Instances of this class allow signing of messages and signature verification, as
 * well as key creation and derivation of a public key from a private key.
 * @param {string} [publicKey] - PEM encoded public key.
 * @param {string} [privateKey] - PEM encoded private key.
 */
export class RSAKey {
    public verifyingKey: string | undefined;
    public signingKey: string | undefined;

    constructor(publicKey?: string, privateKey?: string) {
        if (!publicKey && !privateKey) {
            this._generateNewKeyPair();
            return;
        }

        if (publicKey && typeof publicKey !== 'string') {
            throw new Error('Public key must be PEM encoded.');
        }

        if (privateKey && typeof privateKey !== 'string') {
            throw new Error('Private key must be PEM encoded.');
        }

        this.verifyingKey = publicKey;
        this.signingKey = privateKey;
    }

    get ON_CHAIN_PUB_KEY_NAME(): string {
        return 'publicKeyPem';
    }

    get publicKey(): string | undefined {
        return this.verifyingKey;
    }

    get privateKey(): string | undefined {
        return this.signingKey;
    }

    /**
     * Signs a message with the existing private key. The message is hashed with SHA-256 before being signed.
     * @param {string | Buffer} message - The message to sign.
     * @returns {Buffer} - The bytes of the signature.
     */
    sign(message: string | Buffer): Buffer {
        if (!this.signingKey) {
            throw new Error('Private key is not set.');
        }

        if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
            throw new Error('Message must be a string or Buffer.');
        }

        const sign = createSign('SHA256');
        sign.update(message);
        sign.end();
        return sign.sign(this.signingKey);
    }

    /**
     * Verifies the signature of the given message.
     * @param {string | Buffer} message - The signed message.
     * @param {Buffer | Uint8Array} signature - The signature to verify.
     * @returns {boolean} - True if the signature is successfully verified, False otherwise.
     */
    verify(message: string | Buffer, signature: Buffer | Uint8Array): boolean {
        if (!this.verifyingKey) {
            throw new Error('Public key is not set.');
        }

        if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
            throw new Error('Message must be a string or Buffer.');
        }

        const verify = createVerify('SHA256');
        verify.update(message);
        verify.end();
        return verify.verify(this.verifyingKey, signature);
    }

    private _generateNewKeyPair(): void {
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        this.verifyingKey = publicKey;
        this.signingKey = privateKey;
    }
}
