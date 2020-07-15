export enum Network {
    Mainnet = 'mainnet',
    Testnet = 'testnet',
    Unspecified = ''
}

export enum KeyType {
    EdDSA = 'Ed25519VerificationKey',
    ECDSA = 'ECDSASecp256k1VerificationKey',
    RSA = 'RSAVerificationKey'
}

export enum DIDKeyPurpose {
    PublicKey = 'publicKey',
    AuthenticationKey = 'authenticationKey'
}

export enum EntryType {
    Create = 'DIDManagement',
    Update = 'DIDUpdate',
    Deactivation = 'DIDDeactivation',
    VersionUpgrade = 'DIDMethodVersionUpgrade'
}
