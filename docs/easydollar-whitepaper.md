# EasyDollar: Hardware-Attested Computation Credits Settled on Bitcoin

**A dollar redeemable into computation, secured by TEE attestation and anchored to BTC.**

*Version 0.1 -- Draft*

---

## Abstract

EasyDollar is a computation-denominated unit of account that exists exclusively inside hardware-attested enclaves. One EasyDollar is redeemable for one US dollar worth of enclave computation at current market rates. The token never touches a public blockchain during normal operation -- it lives and moves within the EasyEnclave network of TDX-attested nodes. Settlement to external chains (BTC, USDC, USDT) happens only at ingress and egress, with large settlements secured by Bitcoin's finality. A thin fee layer funds a reserve that provides liquidity across settlement networks.

This paper describes the architecture, the trust model, the fee structure, and the path from the existing EasyEnclave control plane to a self-sustaining computation economy.

---

## 1. Motivation

Cloud computing is billed after the fact, settled through invoices, and denominated in currencies that have no structural relationship to the resource being purchased. This creates three problems:

1. **Counterparty risk.** A deployer trusts that the provider actually ran the workload. A provider trusts that the deployer will pay. Both sides rely on legal agreements rather than cryptographic proof.

2. **Settlement latency.** Payment flows through card networks, ACH, or wire transfers. Days pass between consumption and settlement.

3. **Opacity.** Pricing is a spreadsheet of SKUs. There is no composable unit that represents "one dollar of attested computation" and can be transferred, split, or programmed.

EasyDollar solves all three by making the unit of payment inseparable from the unit of execution. The token only exists inside the same hardware boundary that runs the workload, so holding a balance and spending it are the same operation -- mediated by the CPU, not by a bank.

---

## 2. Background: EasyEnclave Today

EasyEnclave is a confidential discovery service for Intel TDX applications. It already handles:

- **Agent registration with hardware attestation.** Every TDX VM proves its identity via Intel Trust Authority. The control plane verifies MRTD (VM image hash) and RTMRs (runtime memory registers) before admitting an agent to the network.

- **Service deployment and health monitoring.** Deployers publish versioned application images. The control plane matches them to verified agents and monitors uptime.

- **Billing with prepaid accounts.** Deployers fund accounts and are charged per-hour based on vCPUs, memory, GPUs, SLA tier, and machine class. Agents earn 70% of each charge. All transactions are recorded in an immutable ledger.

- **Nonce challenges for replay prevention.** One-time tokens ensure that attestation quotes are fresh, not replayed from a previous session.

The billing system already tracks balances, charges deployments, splits revenue, and terminates workloads on insufficient funds. EasyDollar replaces the USD-denominated balance with a token whose lifecycle is enforced by the enclave itself.

---

## 3. Design Principles

**D1 -- The token exists only inside enclaves.** EasyDollar balances are state held by the attested control plane. There is no ERC-20 contract, no L2 rollup, and no public ledger of balances. The trust anchor is hardware attestation, not blockchain consensus.

**D2 -- Settlement happens at the boundary.** Money enters the system when a user deposits BTC or a chain stablecoin. Money leaves when a user or agent withdraws. Between those events the token circulates inside the enclave network at the speed of a function call.

**D3 -- Large settlements use Bitcoin.** For amounts above a configurable threshold, settlement is routed through Bitcoin. BTC provides final, censorship-resistant settlement that does not depend on any stablecoin issuer's solvency.

**D4 -- Liquidity is self-funded.** The network charges two kinds of fees. A fraction of every fee is reinvested into reserve assets (BTC, USDC, USDT) held across settlement networks, so the system can meet redemptions without external market makers.

**D5 -- The code is the custodian.** No human operator can mint, freeze, or redirect EasyDollars. The control plane binary is measured at boot. Its MRTD is public. Anyone can verify that the running code matches the audited source.

---

## 4. Architecture

### 4.1 Layers

```
                        External World
                   ========================
                   BTC    USDC/USDT   Fiat
                     \       |       /
                      \      |      /
              ┌────────────────────────────┐
              │     Settlement Gateway     │  <-- Runs inside TDX enclave
              │  (deposit / withdraw /     │
              │   BTC relay / bridge)      │
              └────────────────────────────┘
                           |
              ┌────────────────────────────┐
              │     EasyDollar Ledger      │  <-- Enclave-internal state
              │  (balances, tx log,        │
              │   fee collection, reserve) │
              └────────────────────────────┘
                           |
              ┌────────────────────────────┐
              │   EasyEnclave Control Plane │  <-- Attested with MRTD + RTMRs
              │  (agents, deployments,     │
              │   pricing, health)         │
              └────────────────────────────┘
                           |
              ┌────────────────────────────┐
              │      Agent Fleet           │  <-- Each agent is a TDX VM
              │  (workloads, attestation,  │
              │   capacity, earnings)      │
              └────────────────────────────┘
```

### 4.2 The EasyDollar Ledger

The ledger is a table inside the attested control plane database. It replaces the current `accounts` and `transactions` tables with:

| Field | Description |
|-------|-------------|
| `account_id` | UUID, same as today |
| `ed_balance` | EasyDollar balance (1 ED = $1 of computation) |
| `frozen` | Always false; included for schema parity only (no admin freeze) |
| `created_at` | Timestamp |

Every state transition is recorded as a `LedgerEntry`:

| Field | Description |
|-------|-------------|
| `entry_id` | UUID |
| `from_account` | Source account (null for deposits) |
| `to_account` | Destination account (null for withdrawals) |
| `amount_ed` | EasyDollars transferred |
| `fee_ed` | Fee deducted (goes to reserve) |
| `entry_type` | `deposit` / `charge` / `earning` / `transfer` / `withdrawal` |
| `settlement_tx` | External chain txid (for deposits and withdrawals) |
| `created_at` | Timestamp |

The ledger is append-only. The control plane enforces:

- No negative balances.
- No minting without a confirmed deposit.
- No withdrawal without sufficient balance minus pending charges.

Because the ledger runs inside a TDX enclave with a measured binary, these invariants are hardware-enforced. An operator with root on the host machine cannot read or alter enclave memory.

### 4.3 Settlement Gateway

The Settlement Gateway is a module inside the control plane enclave. It holds signing keys for:

- **A BTC wallet** (taproot, multisig with time-locked recovery).
- **Chain stablecoin wallets** (USDC on Ethereum/Base, USDT on Tron, etc.).

Keys are generated inside the enclave at first boot and never leave it. The MRTD of the enclave binary commits to the key derivation path, so anyone can verify that the keys are controlled exclusively by the audited code.

**Deposit flow:**

1. User requests a deposit address from the gateway.
2. Gateway returns a chain-specific address derived from the enclave's master key.
3. User sends BTC or stablecoins to that address.
4. Gateway monitors the chain (via a lightweight client or attested relay).
5. After sufficient confirmations (1 for stablecoins, 3 for BTC), the gateway credits the user's EasyDollar balance at the current exchange rate.

**Withdrawal flow:**

1. User requests withdrawal, specifying chain and destination address.
2. Gateway debits the user's EasyDollar balance.
3. Gateway selects the most liquid settlement path:
   - If the reserve has sufficient stablecoins and the user wants stablecoins: direct transfer.
   - If the user wants BTC or the amount exceeds a threshold: settle via BTC.
4. Gateway signs and broadcasts the transaction from inside the enclave.
5. The `LedgerEntry` records the external txid for auditability.

**Liquidity routing:**

The gateway maintains a simple order of preference:

1. Same-chain, same-asset (cheapest).
2. Cross-chain stablecoin swap via reserve.
3. BTC settlement (highest finality, used for large amounts).

The decision is deterministic and auditable -- it is part of the measured binary.

### 4.4 Reserve Fund

The reserve is a set of on-chain balances controlled by the enclave's keys:

- BTC held in a taproot address.
- USDC held on Ethereum and/or Base.
- USDT held on Tron and/or Ethereum.

The reserve is funded by fees (Section 5). Its purpose is to ensure that withdrawals can be met promptly without depending on external liquidity providers. The control plane periodically rebalances the reserve across chains to match observed withdrawal patterns.

The reserve's on-chain addresses are derived from the enclave's master key and are publicly verifiable. Anyone can audit the reserve by querying the relevant blockchains and comparing the totals to the system's reported liabilities (total EasyDollar balances outstanding).

---

## 5. Fee Structure

The network collects two types of fees:

### 5.1 Capacity Fees

Charged to **deployers** for consuming computation. This replaces the current hourly billing model with an EasyDollar-denominated equivalent:

```
Capacity Fee = Resource Cost + Network Margin

Resource Cost = (vCPUs x $0.04 + RAM_GB x $0.005 + GPUs x $0.50) x SLA_mult x Size_mult
Network Margin = Resource Cost x 0.30    (platform share, same 70/30 split as today)
```

The 30% platform share is decomposed further:

| Destination | Share of Platform 30% | Purpose |
|---|---|---|
| Operations | 60% | Infrastructure, development, support |
| Reserve | 30% | Liquidity for settlement networks |
| Insurance | 10% | Slashing reserve for SLA violations |

So of every dollar spent on computation, 70 cents go to the agent, 18 cents to operations, 9 cents to the reserve, and 3 cents to the insurance pool.

### 5.2 Wallet Fees

Charged for **acting on a third-party network** through the enclave wallet. These are the fees for deposits, withdrawals, and any future cross-chain operations:

| Operation | Fee |
|---|---|
| Deposit (stablecoin) | 0.1% of amount |
| Deposit (BTC) | 0.2% of amount |
| Withdrawal (stablecoin) | 0.1% of amount + chain gas |
| Withdrawal (BTC) | 0.2% of amount + miner fee |
| Internal transfer (ED to ED) | Free |

Wallet fees flow entirely to the reserve. They compensate the network for the cost of maintaining on-chain liquidity and for the risk of holding volatile assets (BTC) between deposit and rebalancing.

### 5.3 Fee Governance

Fees are parameters in the control plane's configuration, committed to the measured binary. Changing fees requires publishing a new version of the control plane, which changes the MRTD. All clients can detect the change and decide whether to continue using the network.

There is no governance token. Fee changes are code changes, subject to the same audit and attestation process as any other update.

---

## 6. Trust Model

### 6.1 What you trust

| Component | Trust basis |
|---|---|
| Intel TDX hardware | Silicon-level isolation, encrypted memory |
| Intel Trust Authority | JWT-signed attestation verification |
| Control plane binary | Open-source, MRTD-committed, auditable |
| Settlement gateway keys | Generated and held inside enclave, never exported |
| Reserve balances | On-chain, publicly auditable |

### 6.2 What you do not trust

| Component | Mitigation |
|---|---|
| Cloud provider | TDX encrypts memory; provider cannot read state |
| Operating system | TDX isolates guest from host OS |
| Network operator | All inter-enclave traffic is authenticated and encrypted |
| Control plane operator | Binary is measured; no admin can mint or freeze tokens |

### 6.3 Failure modes

**Intel TDX compromise.** If a vulnerability is found in TDX itself, the network's TCB enforcement (already implemented) rejects agents with outdated TCB status. The control plane can be migrated to patched hardware. EasyDollar balances are at risk only if the attacker can modify enclave memory before a migration.

**Control plane bug.** A bug in the ledger logic could allow invalid state transitions. Mitigation: the ledger is append-only, the code is open-source, and the reserve is independently auditable on-chain. A discrepancy between the on-chain reserve and the sum of EasyDollar balances is detectable by any observer.

**Chain reorganization.** A deep reorg on BTC or Ethereum could reverse a deposit after EasyDollars were credited. Mitigation: the gateway requires sufficient confirmations (3 for BTC, 12+ for Ethereum) and holds a reorg buffer in the insurance pool.

**Liquidity crunch.** If withdrawal demand exceeds the reserve, the gateway queues withdrawals and processes them as liquidity becomes available (from incoming deposits or reserve rebalancing). The queue is FIFO. No withdrawal is lost, only delayed.

---

## 7. Lifecycle of an EasyDollar

```
1. DEPOSIT
   User sends 100 USDC to the enclave's deposit address.
   Gateway confirms the transaction (12 blocks).
   Ledger credits 99.90 ED to the user (0.1% fee -> reserve).

2. DEPLOY
   User deploys an app to a TDX agent.
   Control plane charges 0.10 ED/hour from the user's balance.
   0.07 ED/hour -> agent account (capacity earning).
   0.018 ED/hour -> operations.
   0.009 ED/hour -> reserve.
   0.003 ED/hour -> insurance.

3. TRANSFER (optional)
   User sends 10 ED to another user inside the network.
   Instant. No fee. Both parties are enclave-internal accounts.

4. EARN
   Agent accumulates 50 ED in earnings.
   Agent requests withdrawal to a BTC address.

5. WITHDRAW
   Gateway debits 50 ED from agent's balance.
   Fee: 0.2% = 0.10 ED -> reserve.
   Gateway sends 49.90 ED worth of BTC (at current rate) to the agent's address.
   Ledger records the BTC txid.
```

---

## 8. Bitcoin Settlement for Large Amounts

For settlements above a configurable threshold (e.g., $10,000), the gateway routes through Bitcoin regardless of the user's preferred chain. The rationale:

- **Finality.** Bitcoin's proof-of-work provides the strongest settlement guarantee available. After 6 confirmations, reversal is economically infeasible.

- **Censorship resistance.** No stablecoin issuer can freeze a BTC transaction in flight.

- **Counterparty minimization.** BTC settlement does not depend on Circle (USDC), Tether (USDT), or any bridge operator. The only counterparty is the Bitcoin network itself.

The gateway converts EasyDollars to BTC at the prevailing rate (sourced from multiple price feeds inside the enclave). The BTC is sent from the enclave's taproot wallet. The recipient receives BTC, which they can hold or convert to their preferred asset independently.

For the sender, the experience is: "I withdrew 50,000 ED and received 0.5 BTC." The routing is transparent in the ledger entry.

---

## 9. From EasyEnclave to EasyDollar: Migration Path

The existing EasyEnclave billing system was designed to evolve into this model. The migration is incremental:

### Phase 1: Internal denomination (current + minor changes)

- Rename `balance` fields to `ed_balance`.
- Add `LedgerEntry` table alongside existing `Transaction` table.
- Deploy the updated control plane with a new MRTD.
- All existing functionality continues. Stripe deposits credit ED. Charges debit ED.

### Phase 2: On-chain deposits

- Add the Settlement Gateway module to the control plane enclave.
- Generate enclave-held keys at first boot.
- Accept BTC and stablecoin deposits.
- Stripe remains as a fallback for fiat on-ramp.

### Phase 3: On-chain withdrawals

- Enable BTC and stablecoin withdrawals from the gateway.
- Implement the reserve fund and fee decomposition.
- Begin accumulating reserve from fees.

### Phase 4: Large BTC settlement

- Implement threshold-based routing to BTC for large settlements.
- Publish the reserve's on-chain addresses for public audit.
- Remove the Stripe dependency (optional; can coexist).

Each phase is a new version of the control plane with a new MRTD. Clients verify the measurement before depositing funds. There is no flag day -- old and new clients coexist.

---

## 10. Comparison to Existing Approaches

| | EasyDollar | USDC/USDT | Lightning | Cloud Credits |
|---|---|---|---|---|
| **Backed by** | Computation + reserve | Fiat deposits | BTC channels | Nothing (prepaid) |
| **Runs on** | TDX enclaves | Ethereum/Tron/etc. | Bitcoin + LN nodes | Provider's servers |
| **Settlement** | BTC for large, stablecoins for small | On-chain transfer | LN payment | Invoice/ACH |
| **Custody** | Hardware enclave (no human keys) | Issuer (Circle/Tether) | Channel operator | Provider |
| **Auditability** | On-chain reserve + attested code | Periodic attestations | Channel state | None |
| **Freezable** | No (no admin controls) | Yes (issuer can freeze) | No | Yes (provider ToS) |
| **Programmable** | Yes (enclave logic) | Yes (smart contracts) | Limited (HTLCs) | No |

---

## 11. Open Questions

1. **Oracle problem.** The gateway needs BTC/USD price data to process deposits and withdrawals. How is this sourced inside the enclave without trusting a single feed? Candidate: aggregate multiple HTTPS price APIs from inside the enclave, reject outliers, use the median.

2. **Key recovery.** If the enclave's master key is lost (hardware failure), funds on external chains are locked. Candidate: Shamir's Secret Sharing across multiple enclave instances, with time-locked Bitcoin recovery paths.

3. **Regulatory classification.** Is EasyDollar a stablecoin, a prepaid access device, or a commodity? The answer varies by jurisdiction and affects whether the network needs money transmitter licenses.

4. **Multi-enclave consensus.** A single control plane instance is a single point of failure. Scaling to multiple attested replicas requires a consensus protocol for the ledger. Candidate: attested Raft, where each replica proves its identity via TDX before joining the quorum.

5. **MEV and front-running.** If the gateway interacts with on-chain DEXs for rebalancing, it could be subject to MEV extraction. Mitigation: use private mempools or direct settlement, avoid AMM interactions for large trades.

---

## 12. Conclusion

EasyDollar is not a cryptocurrency. It is a unit of account for attested computation -- a dollar you can only spend on verifiable workloads, held by hardware you can verify, and settled on chains you choose. The token inherits its trust from the enclave, not from a validator set. Its value comes from the computation it denominates, not from speculation.

The path from EasyEnclave's existing billing system to EasyDollar is short. The control plane already tracks balances, charges hourly, splits revenue, and enforces account limits. EasyDollar wraps that same logic in a settlement layer that connects to Bitcoin and stablecoin networks, funded by fees that the network already collects.

The result is a computation economy where payment and execution happen in the same trust boundary, large settlements are as final as Bitcoin, and the system's reserves are auditable by anyone with a block explorer.

---

## Appendix A: EasyEnclave Primitives Used by EasyDollar

| EasyEnclave Primitive | EasyDollar Usage |
|---|---|
| MRTD verification | Proves the control plane binary (including ledger logic) is unmodified |
| RTMR checking | Detects runtime tampering of enclave state |
| Nonce challenges | Prevents replay of attestation during agent registration |
| TCB enforcement | Rejects agents running on vulnerable hardware |
| 70/30 revenue split | Preserved as the base capacity fee distribution |
| Hourly charging | Converted to ED-denominated charges |
| Immutable transaction log | Becomes the append-only `LedgerEntry` table |
| Background billing tasks | Extended to include reserve rebalancing and settlement processing |

## Appendix B: Reserve Composition Target

The reserve aims to mirror the network's withdrawal demand profile:

| Asset | Target Allocation | Rationale |
|---|---|---|
| BTC | 40% | Large settlement backbone, long-term value store |
| USDC | 35% | Most common stablecoin withdrawal target |
| USDT | 20% | Second most common, covers Tron-based users |
| Operational buffer | 5% | Gas fees, miner fees, unexpected costs |

Rebalancing occurs weekly or when any asset deviates more than 10% from its target. Rebalancing transactions are logged in the ledger and visible on-chain.

## Appendix C: Direct Bitcoin Settlement -- Implementation

The settlement gateway does not depend on any third-party custodian or bridge. The enclave is a native Bitcoin participant: it holds keys, constructs transactions, signs them, and broadcasts them to the Bitcoin P2P network. This appendix describes how.

### C.1 Why Direct Settlement Matters

Every intermediary between the enclave and the Bitcoin network is a point of trust, censorship, and failure. If the gateway sends BTC through an exchange API, the exchange can freeze funds, go offline, or impose KYC on the enclave. If it uses a bridge protocol, the bridge's security model is added to the trust stack. Direct settlement means the only counterparty is the Bitcoin network itself -- 60,000+ nodes with no single point of control.

The enclave wallet is no different from any other Bitcoin wallet. It holds a private key, it constructs and signs transactions according to the Bitcoin protocol, and it broadcasts them to peers. The difference is that the private key exists inside hardware-encrypted memory that the host operator cannot read, and the signing logic is committed to a measurement (MRTD) that anyone can verify.

### C.2 Key Generation

At first boot, the control plane enclave generates a BIP-340 Schnorr keypair for the taproot wallet:

```
master_secret  = os.urandom(32)           # Generated inside TDX-encrypted memory
master_pubkey  = schnorr_pubkey(master_secret)
taproot_address = bech32m_encode(master_pubkey)   # bc1p...
```

The `master_secret` never leaves the enclave. It is persisted to the enclave's encrypted storage (the SQLite database on the dm-verity filesystem). The `taproot_address` is the deposit address published to users.

Key derivation follows BIP-86 (taproot single-key) for simplicity. Each user gets a derived address via BIP-32 child key derivation, so deposits can be attributed to specific accounts without on-chain linkage.

### C.3 Transaction Construction and Signing

The gateway constructs Bitcoin transactions entirely within the enclave using pure Python. The stack:

| Layer | Library | Role |
|---|---|---|
| PSBT construction | **embit** | Build Partially Signed Bitcoin Transactions with taproot inputs/outputs |
| Schnorr signing | **embit** (pure Python secp256k1 fallback) | Sign with BIP-340 Schnorr, no C dependency required |
| Taproot script-path (future) | **python-bitcoin-utils** | Multi-leaf taptrees for recovery and multisig policies |
| Address encoding | **embit** | bech32m for P2TR addresses |

The construction flow for a withdrawal:

```
1. Select UTXOs from the enclave's known UTXO set.
2. Build a PSBT:
   - Input:  enclave's taproot UTXO(s)
   - Output: recipient's address (withdrawal destination)
   - Output: change back to the enclave's taproot address
   - Fee:    estimated from recent feerate (see C.5)
3. Sign the PSBT with the enclave's master key (Schnorr key-path spend).
4. Finalize and extract the raw transaction hex.
5. Broadcast (see C.4).
6. Record the txid in the LedgerEntry.
```

Both `embit` and `python-bitcoin-utils` are pure Python with no mandatory C extensions. This is critical: the enclave's dm-verity root filesystem is read-only and measured. Every byte of code that runs is committed to the MRTD. A pure Python stack means the entire signing path is auditable as source, not as a compiled binary blob.

### C.4 Broadcasting

The enclave broadcasts signed transactions through multiple independent channels for redundancy and censorship resistance:

**Primary: Direct P2P.** The enclave connects to Bitcoin peers discovered via DNS seeds (`seed.bitcoin.sipa.be`, `seed.btc.petertodd.net`, etc.). It performs the version handshake and sends a `tx` message containing the raw transaction. This requires ~200 lines of Python and no special dependencies -- just TCP sockets.

```
Peer discovery:   DNS lookup on well-known seed nodes
Handshake:        version → verack (standard Bitcoin P2P protocol)
Broadcast:        inv(TX, txid) → peer requests getdata → respond with tx
```

The enclave connects to at least 8 peers across different /16 subnets to minimize eclipse risk.

**Fallback: Public Esplora/Mempool APIs.** If P2P connections fail (e.g., network restrictions on the host), the enclave POSTs the raw transaction hex to multiple public APIs:

```
POST https://blockstream.info/api/tx     (Blockstream Esplora)
POST https://mempool.space/api/tx        (mempool.space)
```

These are simple HTTPS calls using `httpx` (already a dependency of EasyEnclave). The enclave tries all endpoints and considers the broadcast successful if any one confirms acceptance.

**Future: Compact Block Filters (BIP-157/158).** For the most trustless lightweight experience without running a full node, the enclave can use BIP-157 compact block filters to verify incoming transactions against block headers. This removes trust in any API server for deposit monitoring while keeping bandwidth minimal.

### C.5 Fee Estimation and UTXO Management

**Fee estimation.** The enclave queries feerate data from multiple sources:

- `GET https://mempool.space/api/v1/fees/recommended` -- returns `fastestFee`, `halfHourFee`, `hourFee` in sat/vB.
- `GET https://blockstream.info/api/fee-estimates` -- returns fee estimates by target confirmation block.

The enclave takes the median across sources for the target confirmation time:
- Withdrawals: target 3 blocks (~30 min). Balances speed against cost.
- Reserve rebalancing: target 6 blocks (~1 hour). Non-urgent.
- Time-sensitive settlements: target next block. Pays premium.

**UTXO tracking.** The enclave maintains a local UTXO set for its addresses. It is updated by:

1. Monitoring the Electrum protocol (`blockchain.scripthash.listunspent`) for the enclave's addresses.
2. Tracking the change outputs of its own transactions.
3. Periodic reconciliation against a public API.

UTXO consolidation runs as a background task during low-fee periods (weekends, late night UTC) to prevent UTXO set bloat from many small deposits.

### C.6 Deposit Monitoring

When a user requests a deposit, the gateway returns a derived taproot address. The enclave then monitors for incoming transactions to that address:

**Electrum subscription (real-time):**
```
blockchain.scripthash.subscribe(sha256(scriptPubKey))
```

This pushes a notification whenever the address's history changes. The enclave then queries the full transaction and counts confirmations.

**Confirmation thresholds:**

| Amount | Required confirmations | Approximate wait |
|---|---|---|
| < $1,000 | 1 confirmation | ~10 minutes |
| $1,000 -- $10,000 | 3 confirmations | ~30 minutes |
| $10,000 -- $100,000 | 6 confirmations | ~1 hour |
| > $100,000 | 6 confirmations + 1 hour hold | ~2 hours |

The hold period for very large deposits provides additional reorg protection beyond raw confirmation count.

### C.7 Time-Locked Recovery

The taproot address includes a script-path leaf with a time-locked recovery clause:

```
Key-path:    enclave master key (normal operation)
Script-path: OP_CHECKSEQUENCEVERIFY(26280 blocks ≈ 6 months) + recovery_key
```

If the enclave is permanently destroyed and keys are lost, a recovery key (held via Shamir's Secret Sharing across N-of-M enclave instances) can sweep the funds after the timelock expires. During normal operation, the key-path spend is used -- it is indistinguishable from any other taproot transaction on-chain (the script-path is hidden in the tweak).

### C.8 Trust Properties

The direct settlement design achieves:

| Property | How |
|---|---|
| **No custodian** | Keys generated and held inside TDX enclave |
| **No bridge** | Direct P2P broadcast to Bitcoin network |
| **No exchange** | BTC/USD rate aggregated from public APIs inside enclave |
| **Auditable signing logic** | Pure Python, measured in MRTD, open source |
| **Censorship resistant** | Multiple independent broadcast paths (P2P + APIs) |
| **Recoverable** | Taproot time-locked script-path with Shamir-split recovery key |
| **Privacy** | Taproot key-path spends are indistinguishable from single-sig |
