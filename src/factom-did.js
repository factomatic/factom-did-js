module.exports = Object.assign(
    {},
    require('./did'),
    require('./enums'),
    require('./keys/management'),
    require('./keys/did'),
    require('./keys/eddsa'),
    require('./keys/ecdsa'),
    require('./keys/rsa')
);
