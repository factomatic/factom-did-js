import { DID_METHOD_NAME } from './constants';
import { KeyType, Network } from './enums';

export function isValidDIDId(didId: string): boolean {
    const regex = new RegExp(
        `^${DID_METHOD_NAME}:(${Network.Mainnet}:|${Network.Testnet}:)?[a-f0-9]{64}$`
    );
    return regex.test(didId);
}

export function validateAlias(alias: string): void {
    const regex = new RegExp('^[a-z0-9-]{1,32}$');
    if (!regex.test(alias)) {
        throw new Error(
            'Alias must not be more than 32 characters long and must contain only lower-case letters, digits and hyphens.'
        );
    }
}

export function validateKeyType(keyType: KeyType): void {
    if (![KeyType.EdDSA, KeyType.ECDSA, KeyType.RSA].includes(keyType)) {
        throw new Error('Type must be a valid signature type.');
    }
}

export function validatePriorityRequirement(priorityRequirement: number | undefined): void {
    if (
        priorityRequirement !== undefined &&
        (!Number.isInteger(priorityRequirement) || priorityRequirement < 0)
    ) {
        throw new Error('Priority requirement must be a non-negative integer.');
    }
}

export function validateServiceEndpoint(endpoint: string): void {
    const regex = new RegExp(
        /^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-/]))?$/
    );
    if (!regex.test(endpoint)) {
        throw new Error('Endpoint must be a valid URL address starting with http:// or https://.');
    }
}
