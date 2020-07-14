import { KeyEntryObject } from './KeyEntryObject';
import { ServiceEntryObject } from './ServiceEntryObject';

export interface DIDDocument {
    didMethodVersion: string;
    managementKey: KeyEntryObject[];
    didKey?: KeyEntryObject[];
    service?: ServiceEntryObject[];
}
