import * as anchor from "@coral-xyz/anchor";
import { assert } from "chai";

describe("vault-missing-signer", () => {
  // Use the default provider that Anchor sets up for `anchor test`
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const connection = provider.connection;
  const opts = anchor.AnchorProvider.defaultOptions();

  // This is the program generated from your IDL
const baseProgram = anchor.workspace.VaultMissingSigner as any;
const idl = baseProgram.idl;

  // Helper: airdrop and confirm
  const airdrop = async (pubkey: anchor.web3.PublicKey, sol = 2) => {
    const sig = await connection.requestAirdrop(
      pubkey,
      sol * anchor.web3.LAMPORTS_PER_SOL
    );
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction(
      { signature: sig, ...latest },
      "confirmed"
    );
  };

  it("shows vulnerable instruction can be called by attacker, secure version blocks attacker", async () => {
    // Create two users: real authority (alice) and attacker (bob)
    const alice = anchor.web3.Keypair.generate();
    const bob = anchor.web3.Keypair.generate();

    await airdrop(alice.publicKey, 2);
    await airdrop(bob.publicKey, 2);

    // Build two providers so we can send txs "as alice" or "as bob"
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

 const aliceProgram = new anchor.Program(idl, aliceProvider);
 const bobProgram = new anchor.Program(idl, bobProvider);

    //
    // A) VULNERABLE FLOW
    //
    const vaultVuln = anchor.web3.Keypair.generate();

    // Alice initializes vault (she becomes authority)
    await aliceProgram.methods
      .initialize()
      .accounts({
        vault: vaultVuln.publicKey,
        authority: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([vaultVuln])
      .rpc();

    // Bob (attacker) calls vulnerable set_authority,
    // passing alice's pubkey as "currentAuthority" (NOT as a signer!)
    await bobProgram.methods
      .setAuthorityVulnerable(bob.publicKey)
      .accounts({
        vault: vaultVuln.publicKey,
        currentAuthority: alice.publicKey,
      })
      .rpc();

    const fetchedVuln = await aliceProgram.account.vault.fetch(
      vaultVuln.publicKey
    );
    assert.ok(
      fetchedVuln.authority.equals(bob.publicKey),
      "Vulnerable version should allow bob to steal authority"
    );

    //
    // B) SECURE FLOW
    //
    const vaultSecure = anchor.web3.Keypair.generate();

    // Alice initializes another vault
    await aliceProgram.methods
      .initialize()
      .accounts({
        vault: vaultSecure.publicKey,
        authority: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([vaultSecure])
      .rpc();

    // Bob tries secure version -> should FAIL because:
    // - vault has_one authority (alice)
    // - but bob is trying to be the "authority" signer
    let failed = false;
    try {
      await bobProgram.methods
        .setAuthoritySecure(bob.publicKey)
        .accounts({
          vault: vaultSecure.publicKey,
          authority: bob.publicKey,
        })
        .rpc();
    } catch (e) {
      failed = true;
    }

    assert.ok(failed, "Secure version should reject bob");

    // Alice calls secure version -> should SUCCEED
    await aliceProgram.methods
      .setAuthoritySecure(bob.publicKey)
      .accounts({
        vault: vaultSecure.publicKey,
        authority: alice.publicKey,
      })
      .rpc();

    const fetchedSecure = await aliceProgram.account.vault.fetch(
      vaultSecure.publicKey
    );
    assert.ok(
      fetchedSecure.authority.equals(bob.publicKey),
      "Secure version should allow only the real authority to change authority"
    );
  });
});
