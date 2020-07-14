import { DIDKeyPurpose, KeyType } from '../enums';

export interface KeyEntryObject {
    id: string;
    type: KeyType;
    controller: string;
    priority?: number;
    purpose?: DIDKeyPurpose[];
    priorityRequirement?: number;
    publicKeyBase58?: string;
    publicKeyPem?: string;
}
