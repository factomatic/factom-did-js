import { createHash } from 'crypto';
import { encode, decode } from 'bs58';
import { sign } from 'tweetnacl/nacl';

/**
 * Representation of an Ed25519 key. Instances of this class allow signing of messages and signature verification, as
 * well as key creation and derivation of a public key from a private key.
 * @param {string | Buffer | Uint8Array} [publicKey] - An optional base58 encoded publicKey or Buffer.
 * @param {string | Buffer | Uint8Array} [privateKey] - An optional base58 encoded privateKey or Buffer.
 */
export class Ed25519Key {
    public verifyingKey!: Uint8Array;
    public signingKey: Uint8Array | undefined;

    constructor(
        publicKey?: string | Buffer | Uint8Array,
        privateKey?: string | Buffer | Uint8Array
    ) {
        if (!publicKey && !privateKey) {
            this._generateNewKeyPair();
            return;
        }

        if (publicKey && typeof publicKey !== 'string' && !Buffer.isBuffer(publicKey)) {
            throw new Error('Public key must be a string or Buffer.');
        }

        if (privateKey && typeof privateKey !== 'string' && !Buffer.isBuffer(privateKey)) {
            throw new Error('Private key must be a string or Buffer.');
        }

        this._deriveSigningAndVerifyingKey(publicKey, privateKey);
    }

    get ON_CHAIN_PUB_KEY_NAME(): string {
        return 'publicKeyBase58';
    }

    get publicKey(): string {
        return encode(Buffer.from(this.verifyingKey));
    }

    get privateKey(): string | undefined {
        if (this.signingKey) {
            return encode(Buffer.from(this.signingKey));
        } else {
            return undefined;
        }
    }

    /**
     * Signs a message with the existing private key. The message is hashed with SHA-256 before being signed.
     * @param {string | Buffer} message - The message to sign.
     * @returns {Uint8Array} - The bytes of the signature.
     */
    sign(message: string | Buffer): Uint8Array {
        if (!this.signingKey) {
            throw new Error('Private key is not set.');
        }

        if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
            throw new Error('Message must be a string or Buffer.');
        }

        const sha256Hash = createHash('sha256');
        sha256Hash.update(message);
        return sign.detached(sha256Hash.digest(), this.signingKey);
    }

    /**
     * Verifies the signature of the given message.
     * @param {string | Buffer} message - The signed message.
     * @param {Buffer | Uint8Array} signature - The signature to verify.
     * @returns {boolean} - True if the signature is successfully verified, False otherwise.
     */
    verify(message: string | Buffer, signature: Buffer | Uint8Array): boolean {
        if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
            throw new Error('Message must be a string or Buffer.');
        }

        const sha256Hash = createHash('sha256');
        sha256Hash.update(message);
        return sign.detached.verify(sha256Hash.digest(), signature, this.verifyingKey);
    }

    private _generateNewKeyPair(): void {
        const keyPair = sign.keyPair();

        this.verifyingKey = keyPair.publicKey;
        this.signingKey = keyPair.secretKey;
    }

    private _deriveSigningAndVerifyingKey(
        publicKey?: string | Buffer | Uint8Array,
        privateKey?: string | Buffer | Uint8Array
    ): void {
        let publicKeyBuffer: Buffer | Uint8Array;
        if (publicKey && typeof publicKey === 'string') {
            publicKeyBuffer = decode(publicKey);
        } else {
            publicKeyBuffer = publicKey as Buffer;
        }

        if (privateKey) {
            let privateKeyBuffer: Buffer | Uint8Array;
            if (typeof privateKey === 'string') {
                privateKeyBuffer = decode(privateKey);
            } else {
                privateKeyBuffer = privateKey;
            }

            const keyPair = sign.keyPair.fromSecretKey(privateKeyBuffer);

            if (
                publicKey &&
                Buffer.compare(Buffer.from(keyPair.publicKey), Buffer.from(publicKeyBuffer)) !== 0
            ) {
                throw new Error(
                    'The provided public key does not match the one derived from the provided private key.'
                );
            }

            this.verifyingKey = keyPair.publicKey;
            this.signingKey = keyPair.secretKey;
        } else {
            if (publicKeyBuffer.length !== 32) {
                throw new Error('Invalid Ed25519 public key. Must be a 32-byte value.');
            }

            this.verifyingKey = publicKeyBuffer;
        }
    }
}
