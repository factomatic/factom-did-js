import { assert } from 'chai';
import { DID, Service } from '../src/factom-did';
import { DID_METHOD_NAME } from '../src/constants';

describe('Test Services', function() {
    it('should add services', function() {
        const firstServiceAlias = 'photo-service';
        const firstServiceType = 'PhotoStreamService';
        const firstServiceEndpoint = 'https://myphoto.com';

        const secondServiceAlias = 'auth-service';
        const secondServiceType = 'AuthenticationService';
        const secondServiceEndpoint = 'https://authenticateme.com';
        const secondServicePriorityRequirement = 2;

        const thirdServiceAlias = 'inbox-service';
        const thirdServiceType = 'SocialWebInboxService';
        const thirdServiceEndpoint = 'https://social.example.com/83hfh37dj';
        const thirdServicePriorityRequirement = 3;
        const thirdServiceCustomFields = {
            description: 'My public social inbox',
            spamCost: {
                amount: '0.50',
                currency: 'USD'
            }
        };

        const did = DID.builder()
            .service(firstServiceAlias, firstServiceType, firstServiceEndpoint)
            .service(
                secondServiceAlias,
                secondServiceType,
                secondServiceEndpoint,
                secondServicePriorityRequirement
            )
            .service(
                thirdServiceAlias,
                thirdServiceType,
                thirdServiceEndpoint,
                thirdServicePriorityRequirement,
                thirdServiceCustomFields
            )
            .build();

        const firstGeneratedService = did.services[0];
        assert.strictEqual(firstGeneratedService.alias, firstServiceAlias);
        assert.strictEqual(firstGeneratedService.serviceType, firstServiceType);
        assert.strictEqual(firstGeneratedService.endpoint, firstServiceEndpoint);
        assert.isUndefined(firstGeneratedService.priorityRequirement);
        assert.isUndefined(firstGeneratedService.customFields);

        const secondGeneratedService = did.services[1];
        assert.strictEqual(secondGeneratedService.alias, secondServiceAlias);
        assert.strictEqual(secondGeneratedService.serviceType, secondServiceType);
        assert.strictEqual(secondGeneratedService.endpoint, secondServiceEndpoint);
        assert.strictEqual(
            secondGeneratedService.priorityRequirement,
            secondServicePriorityRequirement
        );
        assert.isUndefined(secondGeneratedService.customFields);

        const thirdGeneratedService = did.services[2];
        assert.strictEqual(thirdGeneratedService.alias, thirdServiceAlias);
        assert.strictEqual(thirdGeneratedService.serviceType, thirdServiceType);
        assert.strictEqual(thirdGeneratedService.endpoint, thirdServiceEndpoint);
        assert.strictEqual(
            thirdGeneratedService.priorityRequirement,
            thirdServicePriorityRequirement
        );
        assert.strictEqual(thirdGeneratedService.customFields, thirdServiceCustomFields);

        assert.strictEqual(did.services.length, 3);
    });

    it('should throw error if alias is invalid', function() {
        const builder = DID.builder();
        const serviceType = 'PhotoStreamService';
        const serviceEndpoint = 'https://myphoto.com';
        const testCases = ['myDidKey', 'my-d!d-key', 'my_did_key'];
        testCases.forEach(alias => {
            assert.throw(
                () => builder.service(alias, serviceType, serviceEndpoint),
                'Alias must not be more than 32 characters long and must contain only lower-case letters, digits and hyphens.'
            );
        });
    });

    it('should throw error if alias is used', function() {
        const builder = DID.builder();
        const serviceAlias = 'my-photo-service';
        const serviceType = 'PhotoStreamService';
        const serviceEndpoint = 'https://myphoto.com';
        builder.service(serviceAlias, serviceType, serviceEndpoint);
        assert.throw(
            () => builder.service(serviceAlias, serviceType, serviceEndpoint),
            `Duplicate alias "${serviceAlias}" detected.`
        );
    });

    it('should throw error if serviceType is empty or undefined', function() {
        const builder = DID.builder();
        const serviceAlias = 'my-photo-service';
        const serviceEndpoint = 'https://myphoto.com';
        const testCases = ['', undefined];
        testCases.forEach(serviceType => {
            assert.throw(
                () => builder.service(serviceAlias, serviceType as string, serviceEndpoint),
                'Service type is required!'
            );
        });
    });

    it('should throw error if endpoint is invalid', function() {
        const builder = DID.builder();
        const serviceType = 'PhotoStreamService';
        const testCases = ['myservice.com', 'https//myphoto.com'];
        testCases.forEach((endpoint, index) => {
            assert.throw(
                () => builder.service(`service-${index}`, serviceType, endpoint),
                'Endpoint must be a valid URL address starting with http:// or https://.'
            );
        });
    });

    it('should throw error if priorityRequired is invalid', function() {
        const builder = DID.builder();
        const serviceType = 'PhotoStreamService';
        const serviceEndpoint = 'https://myphoto.com';
        const testCases = [-1, -2, 'one', 1.5];
        testCases.forEach((priorityRequirement, index) => {
            assert.throw(
                () =>
                    builder.service(
                        `service-${index}`,
                        serviceType,
                        serviceEndpoint,
                        priorityRequirement as number
                    ),
                'Priority requirement must be a non-negative integer.'
            );
        });
    });

    it('should throw error if customFields is invalid', function() {
        const builder = DID.builder();
        const serviceType = 'PhotoStreamService';
        const serviceEndpoint = 'https://myphoto.com';
        const testCases = [1, 'one'];
        testCases.forEach((customFields, index) => {
            assert.throw(
                () =>
                    builder.service(
                        `service-${index}`,
                        serviceType,
                        serviceEndpoint,
                        undefined,
                        customFields
                    ),
                'Custom fields must be an object!'
            );
        });
    });

    it('should throw error if entry schema version is invalid', function() {
        const didId = `${DID_METHOD_NAME}:db4549470d24534fac28569d0f9c65b5ecef8d6332bc788b4d1b8dc1c2dae13a`;
        const service = new Service('gmail-service', 'EmailService', 'https://gmail.com', 1);
        const entrySchemaVersion = '1.1.0';
        assert.throw(
            () => service.toEntryObj(didId, entrySchemaVersion),
            `Unknown schema version: ${entrySchemaVersion}`
        );
    });
});
