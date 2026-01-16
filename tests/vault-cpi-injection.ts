import * as anchor from "@coral-xyz/anchor";
import { assert } from "chai";
import BN from "bn.js";

describe("vault-cpi-injection", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const connection = provider.connection;
  const opts = anchor.AnchorProvider.defaultOptions();

  const vaultBase = anchor.workspace.VaultCpiInjection as any;
  const vaultIdl = vaultBase.idl;
  const vaultProgramId = vaultBase.programId;

  const paymentLegit = anchor.workspace.PaymentLegit as any;
  const paymentEvil = anchor.workspace.PaymentEvil as any;

  const airdrop = async (pubkey: anchor.web3.PublicKey, sol = 2) => {
    const sig = await connection.requestAirdrop(
      pubkey,
      sol * anchor.web3.LAMPORTS_PER_SOL
    );
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  };

  it("vulnerable deposit lets attacker mint credits without paying; secure deposit blocks evil CPI target", async () => {
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

    // Use 2-arg Program constructor (avoids AccountClient "size" issue)
    const aliceVaultProgram = new anchor.Program(vaultIdl, aliceProvider);
    const bobVaultProgram = new anchor.Program(vaultIdl, bobProvider);

    const paymentLegitId = paymentLegit.programId as anchor.web3.PublicKey;
    const paymentEvilId = paymentEvil.programId as anchor.web3.PublicKey;

    // Vault PDA
    const [vaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      vaultProgramId
    );

    // Credit PDAs
    const [aliceCreditPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("credit"), vaultPda.toBuffer(), alice.publicKey.toBuffer()],
      vaultProgramId
    );
    const [bobCreditPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("credit"), vaultPda.toBuffer(), bob.publicKey.toBuffer()],
      vaultProgramId
    );

    // 1) Initialize vault (Alice pays rent)
    await aliceVaultProgram.methods
      .initializeVault()
      .accounts({
        vault: vaultPda,
        payer: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 2) Init both users
    await aliceVaultProgram.methods
      .initUser()
      .accounts({
        vault: vaultPda,
        userCredit: aliceCreditPda,
        user: alice.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    await bobVaultProgram.methods
      .initUser()
      .accounts({
        vault: vaultPda,
        userCredit: bobCreditPda,
        user: bob.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const amount = new BN(500_000_000); // 0.5 SOL

    const vaultBefore = await connection.getBalance(vaultPda);

    // 3) Alice deposits using SECURE deposit + legit payment program => vault receives SOL
    await aliceVaultProgram.methods
      .depositSecure(amount)
      .accounts({
        vault: vaultPda,
        userCredit: aliceCreditPda,
        user: alice.publicKey,
        paymentProgram: paymentLegitId,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vaultAfterAlice = await connection.getBalance(vaultPda);
    assert.equal(
      vaultAfterAlice - vaultBefore,
      amount.toNumber(),
      "Vault should receive SOL when using legit payment program"
    );

    // 4) Bob deposits using VULNERABLE deposit but points CPI to evil payment program => no SOL moved
    await bobVaultProgram.methods
      .depositVulnerable(amount)
      .accounts({
        vault: vaultPda,
        userCredit: bobCreditPda,
        user: bob.publicKey,
        paymentProgram: paymentEvilId,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vaultAfterBobDeposit = await connection.getBalance(vaultPda);
    assert.equal(
      vaultAfterBobDeposit,
      vaultAfterAlice,
      "Vault should NOT receive SOL when CPI target is evil"
    );

    // Bob still got credited (this is the bug)
    const bobCredit = await bobVaultProgram.account.userCredit.fetch(bobCreditPda);
    assert.equal(
      bobCredit.credits.toString(),
      amount.toString(),
      "Bob should get credits without paying in vulnerable version"
    );

    // 5) Secure deposit should reject evil payment program
    let failed = false;
    try {
      await bobVaultProgram.methods
        .depositSecure(amount)
        .accounts({
          vault: vaultPda,
          userCredit: bobCreditPda,
          user: bob.publicKey,
          paymentProgram: paymentEvilId, // wrong program id
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
    } catch (e) {
      failed = true;
    }
    assert.ok(failed, "Secure deposit should block evil CPI target");

    // 6) Bob withdraws REAL SOL from the vault using fake credits (drains Alice's deposit)
    const bobBalBefore = await connection.getBalance(bob.publicKey);

    await bobVaultProgram.methods
      .withdraw(amount)
      .accounts({
        vault: vaultPda,
        userCredit: bobCreditPda,
        user: bob.publicKey,
      })
      .rpc();

    const bobBalAfter = await connection.getBalance(bob.publicKey);
    assert.ok(bobBalAfter > bobBalBefore, "Bob should receive SOL from vault");

    const vaultAfterWithdraw = await connection.getBalance(vaultPda);
    assert.equal(
      vaultAfterAlice - vaultAfterWithdraw,
      amount.toNumber(),
      "Vault should lose SOL equal to Bob's withdrawal"
    );
  });
});
