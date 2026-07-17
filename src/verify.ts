import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocket } from 'ws';
import * as Rx from 'rxjs';

import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { setNetworkId, getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import * as ledger from '@midnight-ntwrk/ledger-v8';
import { ZswapSecretKeys, DustSecretKey, LedgerParameters } from '@midnight-ntwrk/ledger-v8';
import { type WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { ttlOneHour } from '@midnight-ntwrk/midnight-js-utils';
import { HDWallet, Roles } from '@midnight-ntwrk/wallet-sdk-hd';
import { createKeystore } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import { FluentWalletBuilder, type EnvironmentConfiguration, type DustWalletOptions } from '@midnight-ntwrk/testkit-js';
import { studentWitnesses, studentPrivateStateId, type StudentPrivateState } from './witnesses.js';

// @ts-expect-error Required for GraphQL subscriptions
globalThis.WebSocket = WebSocket;

setNetworkId('preprod');

const ENV: EnvironmentConfiguration = {
  walletNetworkId: 'preprod',
  networkId:'preprod',
  indexer: 'https://indexer.preprod.midnight.network/api/v3/graphql',
  indexerWS:'wss://indexer.preprod.midnight.network/api/v3/graphql/ws',
  node: 'https://rpc.preprod.midnight.network',
  nodeWS: 'wss://rpc.preprod.midnight.network',
  proofServer: 'http://127.0.0.1:6300',
};

const __dirname= path.dirname(fileURLToPath(import.meta.url));
const zkConfigPath = path.resolve(__dirname, '..', 'contract', 'src', 'managed', 'student_credential');
const contractPath = path.join(zkConfigPath, 'contract', 'index.js');
const zkConfigProvider = new NodeZkConfigProvider(zkConfigPath);

function signTransactionIntents(
  tx: { intents?: Map<number, any> },
  signFn: (payload: Uint8Array) => ledger.Signature,
  proofMarker: 'proof'|'pre-proof',
): void {
  if (!tx.intents || tx.intents.size === 0) return;
  for (const segment of tx.intents.keys()) {
    const intent = tx.intents.get(segment);
    if (!intent) continue;
    const cloned = ledger.Intent.deserialize<
      ledger.SignatureEnabled, ledger.Proofish, ledger.PreBinding
    >('signature', proofMarker, 'pre-binding', intent.serialize());
    const signature = signFn(cloned.signatureData(segment));
    if (cloned.fallibleUnshieldedOffer) {
      cloned.fallibleUnshieldedOffer = cloned.fallibleUnshieldedOffer.addSignatures(
        cloned.fallibleUnshieldedOffer.inputs.map((_: any, i: number) =>
          cloned.fallibleUnshieldedOffer!.signatures.at(i) ?? signature)
      );
    }
    if (cloned.guaranteedUnshieldedOffer) {
      cloned.guaranteedUnshieldedOffer = cloned.guaranteedUnshieldedOffer.addSignatures(
        cloned.guaranteedUnshieldedOffer.inputs.map((_: any, i: number) =>
          cloned.guaranteedUnshieldedOffer!.signatures.at(i) ?? signature)
      );
    }
    tx.intents.set(segment, cloned);
  }
}

function isComplete(progress: any): boolean {
  return typeof progress?.isStrictlyComplete === 'function' && progress.isStrictlyComplete();
}

async function syncWallet(wallet: WalletFacade): Promise<void> {
  console.log('Syncing wallet...');
  await Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.filter((s: any) =>
        isComplete(s?.shielded?.state?.progress) &&
        isComplete(s?.dust?.state?.progress) &&
        isComplete(s?.unshielded?.progress)
      ),
      Rx.timeout(250_000),
    )
  );
  console.log('Wallet synced');
}

function getUnshieldedSeed(seed: string): Uint8Array {
  const hdWalletResult = HDWallet.fromSeed(Buffer.from(seed, 'hex'));
  const { hdWallet } = hdWalletResult as { type: 'seedOk'; hdWallet: HDWallet };
  const result = hdWallet.selectAccount(0).selectRole(Roles.NightExternal).deriveKeyAt(0);
  if (result.type === 'keyOutOfBounds') throw new Error('Key derivation out of bounds');
  return result.key;
}

export async function verifyEnrollment(
  masterSeed: string,
  contractAddress: string,
  credential: {
    credentialHash: string;
    issuerSignature: string;
    issuerPublicKey: string;
  },
): Promise<{ verified: boolean; txHash: string; nonce: string; verificationCount: string }> {
  const { hexToBytes, bytesToHex } = await import('@noble/hashes/utils');

  const dustOptions: DustWalletOptions = {
    ledgerParams: LedgerParameters.initialParameters(),
    additionalFeeOverhead: 1_000n,
    feeBlocksMargin: 5,
  };

  const buildResult = await FluentWalletBuilder
    .forEnvironment(ENV)
    .withDustOptions(dustOptions)
    .withSeed(masterSeed)
    .buildWithoutStarting();

  const { wallet, seeds } = buildResult as {
    wallet: WalletFacade;
    seeds: { masterSeed: string; shielded: Uint8Array; dust: Uint8Array };
  };

  const zswapSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const dustSecretKey = DustSecretKey.fromSeed(seeds.dust);

  await wallet.start(zswapSecretKeys, dustSecretKey);
  await syncWallet(wallet);

  const unshieldedKeystore = createKeystore(getUnshieldedSeed(masterSeed), getNetworkId());

  const walletProvider = {
    getCoinPublicKey: () => zswapSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => zswapSecretKeys.encryptionPublicKey,

    async balanceTx(tx: any, ttl: Date = ttlOneHour()) {
      const recipe = await wallet.balanceUnboundTransaction(
        tx,
        { shieldedSecretKeys: zswapSecretKeys, dustSecretKey },
        { ttl },
      );
      const signFn = (payload: Uint8Array) => unshieldedKeystore.signData(payload);
      signTransactionIntents(recipe.baseTransaction, signFn, 'proof');
      if (recipe.balancingTransaction) {
        signTransactionIntents(recipe.balancingTransaction, signFn, 'pre-proof');
      }
      return wallet.finalizeRecipe(recipe);
    },

    submitTx: (tx: any) => wallet.submitTransaction(tx) as any,
  };

  const providers = {
    walletProvider,
    midnightProvider: walletProvider,
    publicDataProvider: indexerPublicDataProvider(ENV.indexer, ENV.indexerWS),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(ENV.proofServer, zkConfigProvider),
    privateStateProvider: levelPrivateStateProvider({
      privateStateStoreName: 'student-verify-state',
      signingKeyStoreName: 'student-verify-signing-keys',
      privateStoragePasswordProvider: () => 'fhnw-zkp-student-2026',
      accountId: zswapSecretKeys.coinPublicKey,
    }),
  };

  const contractModule = await import(pathToFileURL(contractPath).href);
  const compiledContract = CompiledContract.make('student_credential', contractModule.Contract)
    .pipe(
      CompiledContract.withWitnesses(studentWitnesses),
      CompiledContract.withCompiledFileAssets(zkConfigPath),
    );

  const initialPrivateState: StudentPrivateState = {
    credentialHash: hexToBytes(credential.credentialHash),
    issuerSignature: hexToBytes(credential.issuerSignature),
    issuerPublicKey: hexToBytes(credential.issuerPublicKey),
  };

  console.log('Finding deployed contract at:', contractAddress);
  const deployed = await findDeployedContract(providers, {
    compiledContract,
    contractAddress,
    privateStateId: studentPrivateStateId,
    initialPrivateState,
  });

  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const nonceHex = bytesToHex(nonce);
  console.log('Nonce:'+ nonceHex);

  console.log('Generating ZK proof...');
  const result = await deployed.callTx.verify_enrollment(nonce);
  const txHash = result.public.txHash;

  let count = '1';
  try {
    const contractState = await providers.publicDataProvider.queryContractState(contractAddress);
    if (contractState) {
      const ledgerState = contractModule.ledger(contractState.data);
      count = ledgerState.verification_count?.toString() ?? '1';
    }
  } catch(_) {
  }

  console.log('Proof verified! tx:', txHash);
  console.log('Total verifications:', count.toString());

  return {
    verified: true,
    txHash,
    nonce: nonceHex,
    verificationCount: count.toString(),
  };
}