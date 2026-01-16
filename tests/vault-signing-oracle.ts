import * as anchor from "@coral-xyz/anchor";
import { assert } from "chai";
import BN from "bn.js";

describe("vault-signing-oracle", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const connection = provider.connection;
  const opts = anchor.AnchorProvider.defaultOptions();

  const base = anchor.workspace.VaultSigningOracle as any;
  const idl = base.idl;
  const programId = base.programId as anchor.web3.PublicKey;

  const airdrop = async (pubkey: anchor.web3.PublicKey, sol = 2) => {
    const sig = await connection.requestAirdrop(
      pubkey,
      sol * anchor.web3.LAMPORTS_PER_SOL
    );
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  };

  it("attacker drains vault via vulnerable signing oracle; secure withdraw blocks attacker and allows authority", async () => {
    const alice = anchor.web3.Keypair.generate(); // real authority
    const bob = anchor.web3.Keypair.generate();   // attacker

    await airdrop(alice.publicKey, 2);
    await airdrop(bob.publicKey, 2);

    const aliceProvider = new anchor.AnchorProvider(
      connection,
      new anchor.Wallet(alice),
      opts
    );
    const bobProvider = new anchor.AnchorProvider(
      connection,
      new anchor.Wallet(bob),
      opts
    );

    // IMPORTANT: use 2-arg constructor
    const aliceProgram = new anchor.Program(idl, aliceProvider);
    const bobProgram = new anchor.Program(idl, bobProvider);

    // Vault PDA derived from alice
    const [vaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), alice.publicKey.toBuffer()],
      programId
    );

    // 1) Alice initializes vault
    await aliceProgram.methods
      .initialize()
      .accounts({
        vault: vaultPda,
        authority: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 2) Alice deposits 0.5 SOL
    const amount = new BN(500_000_000);

    const vaultBalBefore = await connection.getBalance(vaultPda);

    await aliceProgram.methods
      .deposit(amount)
      .accounts({
        vault: vaultPda,
        depositor: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vaultBalAfterDeposit = await connection.getBalance(vaultPda);
    assert.equal(
      vaultBalAfterDeposit - vaultBalBefore,
      amount.toNumber(),
      "Vault should receive SOL from Alice deposit"
    );

    // 3) Bob drains vault using vulnerable withdraw (recipient=bob)
    const bobBalBefore = await connection.getBalance(bob.publicKey);
    const vaultBalBeforeBobDrain = await connection.getBalance(vaultPda);

    await bobProgram.methods
      .withdrawVulnerable(amount)
      .accounts({
        vault: vaultPda,
        recipient: bob.publicKey,
        caller: bob.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const bobBalAfter = await connection.getBalance(bob.publicKey);
    assert.ok(bobBalAfter > bobBalBefore, "Bob should gain SOL from draining vault");

    const vaultBalAfterBobDrain = await connection.getBalance(vaultPda);
    assert.equal(
      vaultBalBeforeBobDrain - vaultBalAfterBobDrain,
      amount.toNumber(),
      "Vault should lose SOL equal to drained amount"
    );

    // 4) Deposit again so we can test secure behavior
    await aliceProgram.methods
      .deposit(amount)
      .accounts({
        vault: vaultPda,
        depositor: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 5) Bob tries secure withdraw (should FAIL: not authority + recipient rule)
    let failed = false;
    try {
      await bobProgram.methods
        .withdrawSecure(amount)
        .accounts({
          vault: vaultPda,
          authority: bob.publicKey,
          recipient: bob.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
    } catch (e) {
      failed = true;
    }
    assert.ok(failed, "Secure withdraw should reject Bob");

    // 6) Alice can secure-withdraw to herself
    const aliceBalBefore = await connection.getBalance(alice.publicKey);

    await aliceProgram.methods
      .withdrawSecure(amount)
      .accounts({
        vault: vaultPda,
        authority: alice.publicKey,
        recipient: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const aliceBalAfter = await connection.getBalance(alice.publicKey);
    assert.ok(aliceBalAfter > aliceBalBefore, "Alice should receive SOL via secure withdraw");
  });
});
