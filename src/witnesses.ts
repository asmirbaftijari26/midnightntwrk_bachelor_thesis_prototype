import { type WitnessContext } from '@midnight-ntwrk/compact-runtime';

export type IssuerPrivateState = {
  readonly issuerSecretKey: Uint8Array;
};

export type StudentPrivateState = {
  readonly credentialHash:  Uint8Array;
  readonly issuerSignature: Uint8Array;
  readonly issuerPublicKey: Uint8Array;
};

export const issuerPrivateStateId  = 'fhnw-issuer-private-state';
export const studentPrivateStateId = 'fhnw-student-private-state';

export const issuerWitnesses = {

  local_secret_key: (
    ctx: WitnessContext<any, IssuerPrivateState>,
  ): [IssuerPrivateState, Uint8Array] =>
    [ctx.privateState, ctx.privateState.issuerSecretKey],

  get_credential_hash: (
    ctx: WitnessContext<any, IssuerPrivateState>,
  ): [IssuerPrivateState, Uint8Array] => {
    throw new Error('get_credential_hash is not used in the issuer role');
  },

  credential_signature_valid: (
    ctx: WitnessContext<any, IssuerPrivateState>,
    _hash: Uint8Array,
  ): [IssuerPrivateState, boolean] => {
    throw new Error('credential_signature_valid is not used in the issuer role');
  },
};

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const studentWitnesses = {
  local_secret_key: (
    ctx: WitnessContext<any, StudentPrivateState>,
  ): [StudentPrivateState, Uint8Array] => {
    throw new Error('local_secret_key is not used in the student role');
  },

  get_credential_hash: (
    ctx: WitnessContext<any, StudentPrivateState>,
  ): [StudentPrivateState, Uint8Array] =>
    [ctx.privateState, ctx.privateState.credentialHash],

  credential_signature_valid: (
    ctx: WitnessContext<any, StudentPrivateState>,
    credHash: Uint8Array,
  ): [StudentPrivateState, boolean] => {
    const valid = ed.verify(
      ctx.privateState.issuerSignature,
      credHash,
      ctx.privateState.issuerPublicKey,
    );
    return [ctx.privateState, valid];
  },
};