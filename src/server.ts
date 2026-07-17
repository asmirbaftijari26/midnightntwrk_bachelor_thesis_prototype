import express from 'express';
import cors from 'cors';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { issueCredential } from './issuer.js';
import { deployStudentCredentialContract } from './deploy.js';
import { verifyEnrollment } from './verify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const ADDR_FILE = join(ROOT, 'contract-address.json');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(join(ROOT, 'dapp-ui')));

app.get('/api/status', (_req, res) => {
  res.json({
    ok:              true,
    hasIssuerKey: existsSync(join(ROOT, 'issuer-keypair.json')),
    hasCredential: existsSync(join(ROOT, 'student-credential.json')),
    hasContractAddr: existsSync(ADDR_FILE),
    contractAddress: existsSync(ADDR_FILE)
      ? JSON.parse(readFileSync(ADDR_FILE, 'utf-8')).address
      : null,
  });
});

app.post('/api/issue', async (req, res) => {
  try {
    const { studentId, programme, enrolledUntil } = req.body;
    if (!studentId) return res.status(400).json({ error: 'studentId is required' });
    if (!programme) return res.status(400).json({ error: 'programme is required' });
    if (!enrolledUntil) return res.status(400).json({ error: 'enrolledUntil is required' });

    const credential = await issueCredential(studentId, programme, enrolledUntil);

    res.json({
      ok: true,
      credentialHash: credential.credentialHash,
      issuerSignature: credential.issuerSignature,
    });
  } catch (err: any) {
    console.error('[Issue]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/deploy', async (req, res) => {
  try {
    const keyPath = join(ROOT, 'issuer-keypair.json');
    if (!existsSync(keyPath))
      throw new Error('No issuer key. Issue a credential first.');

    const keyPair = JSON.parse(readFileSync(keyPath, 'utf-8'));
    const seed = process.env.WALLET_SEED_HEX;
    if (!seed) throw new Error('WALLET_SEED_HEX not set.');

    const result = await deployStudentCredentialContract(seed, keyPair.privateKey);

    writeFileSync(ADDR_FILE, JSON.stringify({
      address: result.address,
      txHash: result.txHash,
      deployedAt: new Date().toISOString(),
      network: 'preprod',
    }, null, 2));

    res.json({ ok: true, address: result.address, txHash: result.txHash });
  } catch (err: any) {
    console.error('[Deploy]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    if (!existsSync(ADDR_FILE))
      throw new Error('Contract not deployed. Click "Deploy Contract" first.');
    if (!existsSync(join(ROOT, 'student-credential.json')))
      throw new Error('No credential. Click "Issue Credential" first.');

    const { address } = JSON.parse(readFileSync(ADDR_FILE, 'utf-8'));
    const credential = JSON.parse(readFileSync(join(ROOT, 'student-credential.json'), 'utf-8'));
    const seed = process.env.WALLET_SEED_HEX;
    if (!seed) throw new Error('WALLET_SEED_HEX not set.');

    console.log('Starting ZK proof generation...');
    const result = await verifyEnrollment(seed, address, {
      credentialHash: credential.credentialHash,
      issuerSignature: credential.issuerSignature,
      issuerPublicKey: credential.issuerPublicKey,
    });

    res.json({
      ok: true,
      verified: result.verified,
      txHash: result.txHash,
      nonce: result.nonce
    });
  } catch (err: any) {
    console.error('[Verify]', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n Server running`);
  console.log(`UI:  http://localhost:${PORT}/dapp.html`);
});