import { AbstractDIDKey } from './abstract';
import { KeyEntryObject } from '../interfaces/KeyEntryObject';
import { KeyType } from '../enums';

/**
 * A key used to sign updates for an existing DID.
 * @param {string} alias - A human-readable nickname for the key.
 * @param {number} priority - A non-negative integer showing the hierarchical level of the key. Keys with lower
 *   priority override keys with higher priority.
 * @property {KeyType} keyType - Identifies the type of signature that the key pair can be used to generate and verify.
 * @property {string} controller - An entity that controls the key.
 * @property {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have
 *   in order to remove this key.
 * @property {string | Buffer} [publicKey] - A public key.
 * @property {string | Buffer} [privateKey] - A private key.
 */
export class ManagementKey extends AbstractDIDKey {
    public priority: number;

    constructor(
        alias: string,
        priority: number,
        keyType: KeyType,
        controller: string,
        priorityRequirement?: number,
        publicKey?: string | Buffer,
        privateKey?: string | Buffer
    ) {
        super(alias, keyType, controller, priorityRequirement, publicKey, privateKey);

        if (!Number.isInteger(priority) || priority < 0) {
            throw new Error('Priority must be a non-negative integer.');
        }

        this.priority = priority;
    }

    toEntryObj(didId: string, version?: string): KeyEntryObject {
        const entryObj: KeyEntryObject = super.toEntryObj(didId, version);
        entryObj.priority = this.priority;
        return entryObj;
    }
}
