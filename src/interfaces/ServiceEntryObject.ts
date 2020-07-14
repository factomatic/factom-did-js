export interface ServiceEntryObject {
    id: string;
    type: string;
    serviceEndpoint: string;
    priorityRequirement?: number;
    [prop: string]: any;
}
