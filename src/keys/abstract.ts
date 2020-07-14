import { ECDSASecp256k1Key } from './ecdsa';
import { Ed25519Key } from './eddsa';
import { RSAKey } from './rsa';
import { ENTRY_SCHEMA_V100 } from '../constants';
import { KeyEntryObject } from '../interfaces/KeyEntryObject';
import { KeyType } from '../enums';
import {
    isValidDIDId,
    validateAlias,
    validateKeyType,
    validatePriorityRequirement,
} from '../validators';

/**
 * Class representing the common fields and functionality in a ManagementKey and a DIDKey.
 * @param {string} alias - A human-readable nickname for the key.
 * @property {KeyType} keyType - Identifies the type of signature that the key pair can be used to generate and verify.
 * @property {string} controller - An entity that controls the key.
 * @property {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have
 *   in order to remove this key.
 * @property {string | Buffer} [publicKey] - A public key.
 * @property {string | Buffer} [privateKey] - A private key.
 */
export class AbstractDIDKey {
    public alias: string;
    public keyType: KeyType;
    public controller: string;
    public priorityRequirement: number | undefined;
    private _underlyingKey: Ed25519Key | ECDSASecp256k1Key | RSAKey | any;

    constructor(
        alias: string,
        keyType: KeyType,
        controller: string,
        priorityRequirement?: number,
        publicKey?: string | Buffer,
        privateKey?: string | Buffer
    ) {
        this._validateInputParams(alias, keyType, controller, priorityRequirement);

        this.alias = alias;
        this.keyType = keyType;
        this.controller = controller;
        this.priorityRequirement = priorityRequirement;

        if (this.keyType === KeyType.EdDSA) {
            this._underlyingKey = new Ed25519Key(publicKey, privateKey);
        } else if (this.keyType === KeyType.ECDSA) {
            this._underlyingKey = new ECDSASecp256k1Key(publicKey, privateKey);
        } else {
            this._underlyingKey = new RSAKey(publicKey as string, privateKey as string);
        }
    }

    get publicKey(): string | undefined {
        return this._underlyingKey.publicKey;
    }

    get privateKey(): string | undefined {
        return this._underlyingKey.privateKey;
    }

    get verifyingKey(): Buffer | Uint8Array | string | undefined {
        return this._underlyingKey.verifyingKey;
    }

    get signingKey(): Buffer | Uint8Array | string | undefined {
        return this._underlyingKey.signingKey;
    }

    /**
     * Signs a message with the underlying private key. The message is hashed with SHA-256 before being signed.
     * @param {string | Buffer} message - The message to sign.
     * @returns {Uint8Array | Buffer} - The bytes of the signature.
     */
    sign(message: string | Buffer): Buffer | Uint8Array {
        return this._underlyingKey.sign(message);
    }

    /**
     * Verifies the signature of the given message.
     * @param {string | Buffer} message - The signed message.
     * @param {Buffer | Uint8Array} signature - The signature to verify.
     * @returns {boolean} - True if the signature is successfully verified, False otherwise.
     */
    verify(message: string | Buffer, signature: Buffer | Uint8Array): boolean {
        return this._underlyingKey.verify(message, signature);
    }

    /**
     * Builds an object suitable for recording on-chain.
     * @param {string} didId - The DID with which this key is associated. Note that this can be different from the key controller.
     * @param {string} version - The entry schema version
     * @returns {EntryObject} An entry object with `id`, `type`, `controller` and an optional `priorityRequirement` properties. In addition to
     *   those, there is one extra property for the public key: if the selected signature type is SignatureType.RSA,
     *   then this property is called `publicKeyPem`, otherwise it is called `publicKeyBase58`.
     */
    /* istanbul ignore next */
    toEntryObj(didId: string, version: string = ENTRY_SCHEMA_V100): KeyEntryObject {
        if (version === ENTRY_SCHEMA_V100) {
            const entryObj: KeyEntryObject = {
                id: this.fullId(didId),
                type: this.keyType,
                controller: this.controller,
                [this._underlyingKey.ON_CHAIN_PUB_KEY_NAME]: this._underlyingKey.publicKey,
            };

            if (this.priorityRequirement !== undefined) {
                entryObj.priorityRequirement = this.priorityRequirement;
            }

            return entryObj;
        }

        throw new Error(`Unknown schema version: ${version}`);
    }

    /**
     * Generates new key pair for the key.
     */
    rotate(): void {
        if (!this.signingKey) {
            throw new Error('Private key must be set.');
        }

        this._underlyingKey = new this._underlyingKey.constructor();
    }

    /**
     * Constructs the full ID of the key.
     * @param {string} didId
     * @returns {string}
     */
    fullId(didId: string): string {
        return `${didId}#${this.alias}`;
    }

    private _validateInputParams(
        alias: string,
        keyType: KeyType,
        controller: string,
        priorityRequirement: number | undefined
    ): void {
        validateAlias(alias);
        validateKeyType(keyType);

        if (!isValidDIDId(controller)) {
            throw new Error('Controller must be a valid DID Id.');
        }

        validatePriorityRequirement(priorityRequirement);
    }
}
