export default ({ BIP39, Bitcoin, crypto, ed25519, EthHd, taskToPromise }) => {
  const computeSecondPasswordHash = ({ iterations, sharedKey }, password) =>
    crypto.hashNTimes(iterations, sharedKey + password).toString(`hex`)

  const credentialsEntropy = ({ guid, password, sharedKey }) =>
    crypto.sha256(Buffer.from(guid + sharedKey + password))

  const verifySecondPassword = (
    { iterations, sharedKey, storedHash },
    password
  ) => {
    const computedHash = computeSecondPasswordHash(
      { iterations, sharedKey },
      password
    )

    return computedHash === storedHash
  }

  const decryptWithSecondPassword = async (
    { iterations, secondPassword, sharedKey, storedHash },
    cipherText
  ) => {
    if (
      verifySecondPassword(
        { iterations, sharedKey, storedHash },
        secondPassword
      )
    ) {
      return taskToPromise(
        crypto.decryptSecPass(sharedKey, iterations, secondPassword, cipherText)
      )
    } else {
      throw new Error('INVALID_SECOND_PASSWORD')
    }
  }

  const getSeedEntropy = ({
    iterations,
    secondPassword,
    secondPasswordHash,
    seedHex,
    sharedKey
  }) =>
    secondPassword
      ? decryptWithSecondPassword(
          {
            iterations,
            secondPassword,
            sharedKey,
            storedHash: secondPasswordHash
          },
          seedHex
        )
      : seedHex

  const entropyToSeed = entropy =>
    BIP39.mnemonicToSeed(BIP39.entropyToMnemonic(entropy))

  const getSeed = async credentials =>
    entropyToSeed(await getSeedEntropy(credentials))

  const deriveBIP32KeyFromSeedHex = async (
    {
      iterations,
      network,
      secondPassword,
      secondPasswordHash,
      seedHex,
      sharedKey
    },
    path
  ) => {
    const seed = await getSeed({
      iterations,
      secondPassword,
      secondPasswordHash,
      seedHex,
      sharedKey
    })

    return Bitcoin.HDNode.fromSeedBuffer(seed, network)
      .derivePath(path)
      .toBase58()
  }

  // Derivation error using seedHex directly instead of seed derived from
  // mnemonic derived from seedHex
  const deriveLegacyEthereumKey = async credentials => {
    const entropy = await getSeedEntropy(credentials)

    return EthHd.fromMasterSeed(entropy)
      .derivePath(`m/44'/60'/0'/0/0`)
      .getWallet()
      .getPrivateKey()
  }

  const deriveSLIP10ed25519Key = async (credentials, path) => {
    const seed = await getSeed(credentials)
    return ed25519.derivePath(path, seed.toString(`hex`))
  }

  return {
    computeSecondPasswordHash,
    credentialsEntropy,
    decryptWithSecondPassword,
    deriveBIP32KeyFromSeedHex,
    deriveLegacyEthereumKey,
    deriveSLIP10ed25519Key,
    entropyToSeed,
    getSeedEntropy,
    verifySecondPassword
  }
}
