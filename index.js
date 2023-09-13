const EthCrypto = require("eth-crypto");

const identity = EthCrypto.createIdentity();
const compressedPublicKey = EthCrypto.publicKey.compress(identity.publicKey)
const keyPair = {compressedPublicKey, ...identity}

console.info(keyPair);