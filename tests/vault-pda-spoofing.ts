import * as anchor from "@coral-xyz/anchor";
import { assert } from "chai";
import BN from "bn.js";

describe("vault-pda-spoofing", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const connection = provider.connection;
  const opts = anchor.AnchorProvider.defaultOptions();

  const baseProgram = anchor.workspace.VaultPdaSpoofing as any;
  const idl = baseProgram.idl;
  const programId = baseProgram.programId;

  const airdrop = async (pubkey: anchor.web3.PublicKey, sol = 2) => {
    const sig = await connection.requestAirdrop(
      pubkey,
      sol * anchor.web3.LAMPORTS_PER_SOL
    );
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  };

  it("attacker can drain victim vault in vulnerable withdraw; secure withdraw blocks it", async () => {
    const alice = anchor.web3.Keypair.generate();
    const bob = anchor.web3.Keypair.generate();

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

    // IMPORTANT: Use 2-arg Program constructor (avoids the AccountClient size error)
    const aliceProgram = new anchor.Program(idl, aliceProvider);
    const bobProgram = new anchor.Program(idl, bobProvider);

    // Alice's vault PDA address
    const [aliceVault] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), alice.publicKey.toBuffer()],
      programId
    );

    // 1) Alice creates her PDA vault
    await aliceProgram.methods
      .initialize()
      .accounts({
        vault: aliceVault,
        authority: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 2) Alice deposits SOL
    const depositAmount = new BN(500_000_000); // 0.5 SOL

    await aliceProgram.methods
      .deposit(depositAmount)
      .accounts({
        vault: aliceVault,
        authority: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 3) Bob drains Alice's vault using the VULNERABLE withdraw
    await bobProgram.methods
      .withdrawVulnerable(depositAmount)
      .accounts({
        vault: aliceVault,         // <-- victim vault PDA
        authority: bob.publicKey,  // <-- attacker receives funds
      })
      .rpc();

    const afterSteal = await aliceProgram.account.vault.fetch(aliceVault);
    assert.equal(afterSteal.balance.toNumber(), 0, "Bob should drain Alice's balance in vulnerable version");

    // 4) Alice deposits again so we can test secure behavior
    await aliceProgram.methods
      .deposit(depositAmount)
      .accounts({
        vault: aliceVault,
        authority: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 5) Bob tries SECURE withdraw (should FAIL due to seeds constraint)
    let failed = false;
    try {
      await bobProgram.methods
        .withdrawSecure(depositAmount)
        .accounts({
          vault: aliceVault,        // still Alice's vault PDA
          authority: bob.publicKey, // bob is not the PDA owner
        })
        .rpc();
    } catch (e) {
      failed = true;
    }
    assert.ok(failed, "Secure withdraw should block Bob due to PDA seeds validation");

    // 6) Alice can SECURE withdraw successfully
    await aliceProgram.methods
      .withdrawSecure(depositAmount)
      .accounts({
        vault: aliceVault,
        authority: alice.publicKey,
      })
      .rpc();

    const finalState = await aliceProgram.account.vault.fetch(aliceVault);
    assert.equal(finalState.balance.toNumber(), 0, "Alice should withdraw successfully in secure version");
  });
});
