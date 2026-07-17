import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const KEY_FILE = join(ROOT, 'issuer-keypair.json');
const CREDENTIAL_FILE = join(ROOT, 'student-credential.json');

export interface EnrollmentData {
  studentId: string;
  institution: string;
  programme: string;
  enrolledUntil: string;
  issuedAt: string;
}

export interface StudentCredential {
  enrollmentData: EnrollmentData;
  credentialHash: string;
  issuerSignature: string;
  issuerPublicKey: string;
}

export interface IssuerKeyPair {
  privateKey: string;
  publicKey: string;
}

export async function loadOrGenerateKeyPair(): Promise<IssuerKeyPair> {
  if (existsSync(KEY_FILE)) {
    return JSON.parse(readFileSync(KEY_FILE, 'utf-8'));
  }
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const keyPair= { privateKey: bytesToHex(privateKey), publicKey: bytesToHex(publicKey) };
  writeFileSync(KEY_FILE, JSON.stringify(keyPair, null, 2));
  return keyPair;
}

export function simulateLogin(studentId: string, programme: string, enrolledUntil: string): EnrollmentData {
  return {
    studentId,
    institution:'FHNW',
    programme,
    enrolledUntil,
    issuedAt: new Date().toISOString(),
  };
}

export function hashEnrollmentData(data: EnrollmentData): Uint8Array {
  const canonical = JSON.stringify(data, Object.keys(data).sort());
  return sha256(new TextEncoder().encode(canonical));
}

export async function issueCredential(
  studentId: string,
  programme: string,
  enrolledUntil: string,
): Promise<StudentCredential> {
  const keyPair = await loadOrGenerateKeyPair();
  const enrollment = simulateLogin(studentId, programme, enrolledUntil);
  const hashBytes = hashEnrollmentData(enrollment);
  const sigBytes = await ed.signAsync(hashBytes, hexToBytes(keyPair.privateKey));

  const credential: StudentCredential = {
    enrollmentData: enrollment,
    credentialHash: bytesToHex(hashBytes),
    issuerSignature: bytesToHex(sigBytes),
    issuerPublicKey: keyPair.publicKey,
  };

  writeFileSync(CREDENTIAL_FILE, JSON.stringify(credential, null, 2));
  return credential;
}