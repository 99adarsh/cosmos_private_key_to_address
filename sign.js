const bech32 = require('bech32');
const createHash = require('create-hash');
const secp256k1 = require('secp256k1');
const jsonStringify = require('fast-json-stable-stringify');
const bip39 = require('bip39');
const bip32 = require('bip32');

// the code of `seedToPrivateKey` is derived from @lunie/cosmos-key
// https://github.com/luniehq/cosmos-keys/blob/2586e7af82fc52c2c2603383e850a1969539f4f1/src/cosmos-keys.ts
function seedToPrivateKey(mnemonic, hdPath = `m/44'/118'/0'/0/0`) {
  const seed = bip39.mnemonicToSeedSync(mnemonic)
  const masterKey = bip32.fromSeed(seed)
  const { privateKey } = masterKey.derivePath(hdPath)
  return privateKey
}

function createSigner(privateKey) {
  console.log(`private key: ${privateKey.toString('hex')}`);
  const publicKeyArr = secp256k1.publicKeyCreate(privateKey, true);
  const publicKey = Buffer.from(publicKeyArr);
  for (let i=0; i<publicKey.length; i++) {
    console.log("publickey : ",publicKey[i])
  }
  console.log(`public key direct: ${publicKey}`);
  console.log(`public key: ${publicKey.toString('base64')}`);
  const sha256 = createHash('sha256');
  const ripemd = createHash('ripemd160');
  sha256.update(publicKey);
  let digest = sha256.digest();
  for (let i=0; i<digest.length; i++) {
    console.log("Digest : ",digest[i])
  }
  console.log(`Sha256 ${digest}`);
  ripemd.update(digest);
  const rawAddr = ripemd.digest();
  for (let i=0; i<rawAddr.length; i++) {
    console.log("rawAddr : ",rawAddr[i])
  }
  console.log("Becccc ",bech32.bech32.toWords(rawAddr))
  const cosmosAddress = bech32.bech32.encode('cosmos', bech32.bech32.toWords(rawAddr));
//   const cosmosAddress = bech32.encode('cosmos', bech32.toWords(rawAddr));
  console.log(`address: ${cosmosAddress}`);
  const sign = (msg) => {
    const msgSha256 = createHash('sha256');
    msgSha256.update(msg);
    const msgHash = msgSha256.digest();
    const { signature: signatureArr } = secp256k1.ecdsaSign(msgHash, privateKey);
    const signature = Buffer.from(signatureArr)
    console.log(`signature: ${signature.toString('base64')}`);
    return { signature, publicKey };
  }
  return { cosmosAddress, sign };
}

const privKey = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
// may also derive private key from seed words:
// const seed = "novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel novel";
// const privKey = seedToPrivateKey(seed);
const signer = createSigner(privKey);
console.log(`Signer : ${signer}`);

// private key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
// public key: A0ZGrlBHMWtCMNAIbIrOxofwCxzZ0dxjT2yzWKwKmo//
// address: cosmos1mnyn7x24xj6vraxeeq56dfkxa009tvhgknhm04
// signature: iBIA5d+tZ99hlcjdzvpm8/eHtK31kblp1lCHWb4CSzEQUm/Wns/emogUn6VsSQVt2eYPpLjnfNXas5PMgWzdnw==