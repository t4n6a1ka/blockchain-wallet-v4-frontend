// Functions that require sensitive information to perform (e.g., password,
// seed, and sharedKey).  Think of this module as similar to a Hardware Security
// Module.

import BIP39 from 'bip39'
import Bitcoin from 'bitcoinjs-lib'
import * as ed25519 from 'ed25519-hd-key'
import { pipe } from 'ramda'
import { view } from 'ramda-lens'

import * as selectors from '../redux/wallet/selectors'
import Core from './core'
import * as types from '../types'
import { taskToPromise } from '../utils/functional'
import * as crypto from '../walletCrypto'

const core = Core({ BIP39, Bitcoin, crypto, ed25519, taskToPromise })

const getSecondPasswordHash = pipe(
  selectors.getWallet,
  view(types.Wallet.dpasswordhash)
)

const getSeedHex = pipe(
  selectors.getDefaultHDWallet,
  view(types.HDWallet.seedHex)
)

export default ({ http, rootUrl, store }) => {
  const computeSecondPasswordHash = secondPassword => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const sharedKey = selectors.getSharedKey(state)

    return core.computeSecondPasswordHash(
      { iterations, sharedKey },
      secondPassword
    )
  }

  const credentialsEntropy = ({ guid }) => {
    const state = store.getState()
    const password = selectors.getMainPassword(state)
    const sharedKey = selectors.getSharedKey(state)
    return core.credentialsEntropy({ guid, password, sharedKey })
  }

  const decryptWithSecondPassword = ({ secondPassword }, cipherText) => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const sharedKey = selectors.getSharedKey(state)
    const storedHash = getSecondPasswordHash(state)

    return core.decryptWithSecondPassword(
      { iterations, secondPassword, sharedKey, storedHash },
      cipherText
    )
  }

  const encryptWithSecondPassword = ({ secondPassword }, plaintext) => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const sharedKey = selectors.getSharedKey(state)

    return taskToPromise(
      crypto.encryptSecPass(sharedKey, iterations, secondPassword, plaintext)
    )
  }

  const deriveBIP32Key = async ({ network, secondPassword }, path) => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const secondPasswordHash = getSecondPasswordHash(state)
    const seedHex = getSeedHex(state)
    const sharedKey = selectors.getSharedKey(state)

    return core.deriveBIP32KeyFromSeedHex(
      {
        iterations,
        network,
        secondPassword,
        secondPasswordHash,
        seedHex,
        sharedKey
      },
      path
    )
  }

  // Derivation error using seedHex directly instead of seed derived from
  // mnemonic derived from seedHex
  const deriveLegacyEthereumKey = async ({ secondPassword }) => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const secondPasswordHash = getSecondPasswordHash(state)
    const seedHex = getSeedHex(state)
    const sharedKey = selectors.getSharedKey(state)

    return core.deriveLegacyEthereumKey({
      iterations,
      secondPassword,
      secondPasswordHash,
      seedHex,
      sharedKey
    })
  }

  const deriveSLIP10ed25519Key = async ({ secondPassword }, path) => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const secondPasswordHash = getSecondPasswordHash(state)
    const seedHex = getSeedHex(state)
    const sharedKey = selectors.getSharedKey(state)

    return core.deriveSLIP10ed25519Key(
      {
        iterations,
        secondPassword,
        secondPasswordHash,
        seedHex,
        sharedKey
      },
      path
    )
  }

  const verifySecondPassword = password => {
    const state = store.getState()
    const iterations = selectors.getPbkdf2Iterations(state)
    const sharedKey = selectors.getSharedKey(state)
    const storedHash = getSecondPasswordHash(state)

    return core.verifySecondPassword(
      { iterations, sharedKey, storedHash },
      password
    )
  }

  const getSettings = guid => {
    const state = store.getState()
    const sharedKey = selectors.getSharedKey(state)

    return http.post({
      url: rootUrl,
      endPoint: '/wallet',
      data: { guid, sharedKey, method: 'get-info', format: 'json' }
    })
  }

  const updateSettings = (guid, method, payload, querystring = '') => {
    const state = store.getState()
    const sharedKey = selectors.getSharedKey(state)

    return http.post({
      url: rootUrl,
      endPoint: querystring ? `/wallet?${querystring}` : '/wallet',
      data: { guid, sharedKey, method, payload, length: (payload + '').length }
    })
  }

  return {
    computeSecondPasswordHash,
    credentialsEntropy,
    decryptWithSecondPassword,
    encryptWithSecondPassword,
    deriveBIP32Key,
    deriveLegacyEthereumKey,
    deriveSLIP10ed25519Key,
    getSettings,
    updateSettings,
    verifySecondPassword
  }
}
