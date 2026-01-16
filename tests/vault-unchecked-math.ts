import * as anchor from "@coral-xyz/anchor";
import { assert } from "chai";
import BN from "bn.js";

describe("vault-unchecked-math", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const connection = provider.connection;
  const opts = anchor.AnchorProvider.defaultOptions();

  const baseProgram = anchor.workspace.VaultUncheckedMath as any;
  const idl = baseProgram.idl;
  const programId = baseProgram.programId as anchor.web3.PublicKey;

  const airdrop = async (pubkey: anchor.web3.PublicKey, sol = 2) => {
    const sig = await connection.requestAirdrop(
      pubkey,
      sol * anchor.web3.LAMPORTS_PER_SOL
    );
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  };

  it("secure withdraw blocks attacker; vulnerable withdraw lets attacker drain due to wrapping underflow", async () => {
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

    // IMPORTANT: 2-arg Program constructor (avoids the AccountClient "size" issue)
    const aliceProgram = new anchor.Program(idl, aliceProvider);
    const bobProgram = new anchor.Program(idl, bobProvider);

    // Vault PDA
    const [vaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      programId
    );

    // Credit PDAs
    const [aliceCreditPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("credit"), vaultPda.toBuffer(), alice.publicKey.toBuffer()],
      programId
    );
    const [bobCreditPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("credit"), vaultPda.toBuffer(), bob.publicKey.toBuffer()],
      programId
    );

    // 1) Initialize vault (Alice pays rent)
    await aliceProgram.methods
      .initializeVault()
      .accounts({
        vault: vaultPda,
        payer: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 2) Init user accounts
    await aliceProgram.methods
      .initUser()
      .accounts({
        vault: vaultPda,
        userCredit: aliceCreditPda,
        user: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    await bobProgram.methods
      .initUser()
      .accounts({
        vault: vaultPda,
        userCredit: bobCreditPda,
        user: bob.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 3) Alice deposits 0.5 SOL
    const depositAmount = new BN(500_000_000);
    await aliceProgram.methods
      .deposit(depositAmount)
      .accounts({
        vault: vaultPda,
        userCredit: aliceCreditPda,
        user: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 4) Alice withdraws 0.2 SOL securely (prove legit flow works)
    const aliceWithdraw = new BN(200_000_000);

    const vaultBalBeforeAliceWithdraw = await connection.getBalance(vaultPda);

    await aliceProgram.methods
      .withdrawSecure(aliceWithdraw)
      .accounts({
        vault: vaultPda,
        userCredit: aliceCreditPda,
        user: alice.publicKey,
      })
      .rpc();

    const vaultBalAfterAliceWithdraw = await connection.getBalance(vaultPda);
    assert.equal(
      vaultBalBeforeAliceWithdraw - vaultBalAfterAliceWithdraw,
      aliceWithdraw.toNumber(),
      "Vault should lose exactly aliceWithdraw lamports in secure withdraw"
    );

    // Remaining vault balance should be 0.3 SOL
    const vaultStateAfterAlice = await aliceProgram.account.vault.fetch(vaultPda);
    assert.equal(
      vaultStateAfterAlice.balance.toNumber(),
      300_000_000,
      "Vault internal balance should track remaining deposits"
    );

    // 5) Bob tries SECURE withdraw of 0.3 SOL (should FAIL: bob has 0 credits)
    const bobSteal = new BN(300_000_000);

    let failed = false;
    try {
      await bobProgram.methods
        .withdrawSecure(bobSteal)
        .accounts({
          vault: vaultPda,
          userCredit: bobCreditPda,
          user: bob.publicKey,
        })
        .rpc();
    } catch (e) {
      failed = true;
    }
    assert.ok(failed, "Secure withdraw should reject bob with 0 credits");

    // 6) Bob uses VULNERABLE withdraw (should SUCCEED)
    const vaultBalBeforeBob = await connection.getBalance(vaultPda);
    const bobBalBefore = await connection.getBalance(bob.publicKey);

    await bobProgram.methods
      .withdrawVulnerable(bobSteal)
      .accounts({
        vault: vaultPda,
        userCredit: bobCreditPda,
        user: bob.publicKey,
      })
      .rpc();

    const vaultBalAfterBob = await connection.getBalance(vaultPda);
    assert.equal(
      vaultBalBeforeBob - vaultBalAfterBob,
      bobSteal.toNumber(),
      "Vault should lose exactly bobSteal lamports in vulnerable withdraw"
    );

    const bobBalAfter = await connection.getBalance(bob.publicKey);
    assert.ok(bobBalAfter > bobBalBefore, "Bob should receive lamports (net of fees still positive)");

    // Bob credits should now be HUGE due to wrapping underflow
    const bobCredit = await bobProgram.account.userCredit.fetch(bobCreditPda);
    assert.ok(
      bobCredit.credits.gt(bobSteal),
      "Bob credits should become a huge number due to wrapping underflow"
    );
  });
});
