import BIP39 from 'bip39'
import Bitcoin from 'bitcoinjs-lib'
import * as ed25519 from 'ed25519-hd-key'
import EthHd from 'ethereumjs-wallet/hdkey'
import * as StellarSdk from 'stellar-sdk'

import Core from './core'
import * as crypto from '../walletCrypto'
import { taskToPromise } from '../utils/functional'

const core = Core({ BIP39, Bitcoin, crypto, ed25519, EthHd, taskToPromise })

it(`computes a hash for checking the validity of the second password`, () => {
  expect(
    core.computeSecondPasswordHash(
      {
        iterations: 5000,
        sharedKey: `a59a510d-433a-4b11-8f7f-6bacfa1f0f2d`
      },
      `password`
    )
  ).toEqual(`1227dd6bc52eb8d32767c9ebc0ec4004db148b15ee332bc8b8ebdfb5ad97371a`)
})

it(`generates entropy from the user's credentials`, () => {
  expect(
    core
      .credentialsEntropy({
        guid: `50dae286-e42e-4d67-8419-d5dcc563746c`,
        password: `password`,
        sharedKey: `b91c904b-53ab-44b1-bf79-5b60c018da15`
      })
      .toString(`base64`)
  ).toEqual(`jqdTiIA0jYETn9EjAGljE5697lc8kSkxod79srxfLug=`)
})

describe(`decryptWithSecondPassword`, () => {
  it(`decrypts with a second password`, async () => {
    expect(
      await core.decryptWithSecondPassword(
        {
          iterations: 5000,
          secondPassword: `second password`,
          sharedKey: `a59a510d-433a-4b11-8f7f-6bacfa1f0f2d`,
          storedHash: `d18e46451956a13c15a3ec2a09164f012212ef4488a63df230df292079d969c2`
        },
        `bKcNwis6TlK2SHRvxqESO+afPtLiNgcoLmqab/F816AVUgnbu+Gc3Bdcf5MAVjBew3mrhpS2Wbrtlg/DzBFMkA==`
      )
    ).toEqual(`3b5fbf176a2462a02d4aa2b79b56482d`)
  })

  it(`throws an error while decrypting with the wrong password`, () => {
    expect(
      core.decryptWithSecondPassword(
        {
          iterations: 5000,
          secondPassword: `wrong password`,
          sharedKey: `a59a510d-433a-4b11-8f7f-6bacfa1f0f2d`,
          storedHash: `d18e46451956a13c15a3ec2a09164f012212ef4488a63df230df292079d969c2`
        },
        `bKcNwis6TlK2SHRvxqESO+afPtLiNgcoLmqab/F816AVUgnbu+Gc3Bdcf5MAVjBew3mrhpS2Wbrtlg/DzBFMkA==`
      )
    ).rejects.toEqual(new Error('INVALID_SECOND_PASSWORD'))
  })
})

describe(`getSeedEntropy`, () => {
  it(`doesn't decrypt the seedHex if there's no second password`, async () => {
    expect(
      await core.getSeedEntropy({ seedHex: `b8370dee9c086bb87b81cc8b72278eb2` })
    ).toEqual(`b8370dee9c086bb87b81cc8b72278eb2`)
  })

  it(`decrypts the entropy if there's a second password`, async () => {
    const seedHex = `W+fDKp18lpsdCzuko5sJJtpIQ176fRDrOzDUOMQtZSEAxwST7Hrkim+u7A/FxcqW0H5ItWzJCc8yPMAAAtFThw==`

    expect(
      await core.getSeedEntropy({
        iterations: 5000,
        secondPassword: `password`,
        secondPasswordHash: `1227dd6bc52eb8d32767c9ebc0ec4004db148b15ee332bc8b8ebdfb5ad97371a`,
        seedHex,
        sharedKey: `a59a510d-433a-4b11-8f7f-6bacfa1f0f2d`
      })
    ).toEqual(`3b5fbf176a2462a02d4aa2b79b56482d`)
  })
})

it(`entropyToSeed`, () => {
  expect(
    core.entropyToSeed(`713a3ae074e60e56c6bd0557c4984af1`).toString(`base64`)
  ).toEqual(
    `5KWmMucJQ65/B2Wd8TMhYJN/rYJYchakxkMVoPs5SX7koB923atMumgUeXfzoUe2rVhMQYCOgjigf2zEtYLxhg==`
  )
})

it(`derives a BIP32 key from seedHex`, async () => {
  expect(
    await core.deriveBIP32KeyFromSeedHex(
      {
        network: Bitcoin.networks.bitcoin,
        seedHex: `713a3ae074e60e56c6bd0557c4984af1`
      },
      `m/0`
    )
  ).toEqual(
    `xprv9vJpjafE9tbBCPBrcv5hBq1tUP4s4d3kZRHewAkGwzjvPZ3Jm8nt9eYwoLUcjnBKdB46WZmzuoEqWLJNB2GwyfShQ1y3Pn7AoVsGYXgzabG`
  )
})

// Derivation error using seedHex directly instead of seed derived from
// mnemonic derived from seedHex
it(`derives a legacy Ethereum key from seedHex`, async () => {
  expect(
    (await core.deriveLegacyEthereumKey({
      seedHex: `e39c77ed95097f9006c34e1a843aa151`
    })).toString(`hex`)
  ).toEqual(`bb9c3e500b9c41ce9836619fb840436c2d98695d6dc43fb73e6e02df7ee7fc5c`)
})

describe(`derives a SLIP-10 ed25519 key from the seed`, () => {
  const testVectors = [
    {
      seedHex: '713a3ae074e60e56c6bd0557c4984af1',
      publicKey: 'GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6',
      secret: 'SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN'
    },
    {
      seedHex: 'b781c27351c7024355cf7f0b0efdc7f85e046cf9',
      publicKey: 'GAVXVW5MCK7Q66RIBWZZKZEDQTRXWCZUP4DIIFXCCENGW2P6W4OA34RH',
      secret: 'SAKS7I2PNDBE5SJSUSU2XLJ7K5XJ3V3K4UDFAHMSBQYPOKE247VHAGDB'
    },
    {
      seedHex:
        '150df9e3ab10f3f8f1428d723a6539662e181ec8781355396cec5fc2ce08d760',
      publicKey: 'GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ',
      secret: 'SAEWIVK3VLNEJ3WEJRZXQGDAS5NVG2BYSYDFRSH4GKVTS5RXNVED5AX7'
    },
    {
      seedHex: '00000000000000000000000000000000',
      publicKey: 'GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX',
      secret: 'SBUV3MRWKNS6AYKZ6E6MOUVF2OYMON3MIUASWL3JLY5E3ISDJFELYBRZ'
    }
  ]

  it(`verifySecondPassword`, () => {
    expect(
      core.verifySecondPassword(
        {
          iterations: 5000,
          sharedKey: `a59a510d-433a-4b11-8f7f-6bacfa1f0f2d`,
          storedHash: `1227dd6bc52eb8d32767c9ebc0ec4004db148b15ee332bc8b8ebdfb5ad97371a`
        },
        `password`
      )
    ).toEqual(true)
  })

  testVectors.forEach(({ publicKey, secret, seedHex }, index) => {
    it(`test vector ${index}`, async () => {
      const { key } = await core.deriveSLIP10ed25519Key(
        { seedHex: Buffer.from(seedHex, `hex`) },
        `m/44'/148'/0'`
      )

      const keypair = StellarSdk.Keypair.fromRawEd25519Seed(key)
      expect(keypair.publicKey()).toEqual(publicKey)
      expect(keypair.secret()).toEqual(secret)
    })
  })
})
