const util = require('util');
const KeyStore = require('./keystore');
const Nacl = require('tweetnacl');
const NaclUtil = require('tweetnacl-util');
const Encryption = require('./encryption');

export type EncryptString = {
  encStr: string;
  nonce: string;
};

export type Key = {
  privKey: string;
  encPrivKey: string;
};

const createVault = util.promisify(KeyStore.createVault);
const deriveKeyFromPasswordAndSalt = util.promisify(KeyStore.deriveKeyFromPasswordAndSalt);

export const generateMnemonic = (): string => {
  var seed = '';
  while (seed.length === 0) {
    const rawSeed = KeyStore.generateRandomSeed();
    if (KeyStore.isSeedValid(rawSeed)) {
      seed = rawSeed;
    }
  }
  return seed;
};

export const generateKeystoreWithMnemonic = async (mnemonic: string, password: string) => {
  if (!KeyStore.isSeedValid(mnemonic)) {
    throw new Error('mnemonic invalid');
  }
  const keystore = await createVault({
    hdPathString: "m/0'/0'/0'",
    seedPhrase: mnemonic,
    password: password,
  });
  const pwDerivedKey = await deriveKeyFromPasswordAndSalt(password, keystore.salt);
  const newKeys = keystore._generatePrivKeys(pwDerivedKey, 1) as Key[];
  const key = newKeys[0];

  return {
    serializedKeystore: keystore.serialize(),
    pkey: key.privKey,
  };
};

export const isSeedValid = (mnemonic: string): boolean => {
  return KeyStore.isSeedValid(mnemonic)
}

export const createPkeyFromMnemonic = async (mnemonic: string) => {
  const keystore = await createVault({
    hdPathString: "m/0'/0'/0'",
    seedPhrase: mnemonic,
    password: '',
  });
  const pwDerivedKey = await deriveKeyFromPasswordAndSalt('', keystore.salt);
  const newKeys = keystore._generatePrivKeys(pwDerivedKey, 1) as Key[];
  return newKeys[0];
};

export const getPkeyWithPassword = async (existingSerializedKeystore: string, password: string): Promise<Key> => {
  const existingKeystore = KeyStore.deserialize(existingSerializedKeystore);
  existingKeystore.hdIndex = 0;
  const pwDerivedKey = await deriveKeyFromPasswordAndSalt(password, existingKeystore.salt);
  const keys = existingKeystore._generatePrivKeys(pwDerivedKey, 1);
  return keys[0];
};

export const encryptString = (pkey: string, contentStr: string): EncryptString => {
  const decKey = Encryption.decodeHex(pkey);
  const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
  const encStr = Nacl.secretbox(NaclUtil.decodeUTF8(contentStr), nonce, decKey);

  return {
    encStr: NaclUtil.encodeBase64(encStr),
    nonce: NaclUtil.encodeBase64(nonce),
  };
};

export const decryptString = (pkey: string, encryptedStr: EncryptString) => {
  const decKey = Encryption.decodeHex(pkey);
  const decStr = NaclUtil.decodeBase64(encryptedStr.encStr);
  const nonce = NaclUtil.decodeBase64(encryptedStr.nonce);

  const decryptedStr = Nacl.secretbox.open(decStr, nonce, decKey);

  if (decryptedStr === null) {
    return false;
  }

  return NaclUtil.encodeUTF8(decryptedStr);
};
