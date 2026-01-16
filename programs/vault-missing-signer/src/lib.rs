use anchor_lang::prelude::*;

declare_id!("Gs9TPn7LwjpoSwsc9juKqTA9owmxYA63Cxzwr8RbKEBp");

#[program]
pub mod vault_missing_signer {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.vault.authority = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn set_authority_vulnerable(
        ctx: Context<SetAuthorityVulnerable>,
        new_authority: Pubkey,
    ) -> Result<()> {
        // ❌ Vulnerable:
        // We only check that the provided "current_authority" pubkey matches the vault.authority pubkey.
        // But we DO NOT require current_authority to be a SIGNER.
        //
        // Attacker can pass the real authority pubkey as a normal (non-signer) account and still pass.
        require_keys_eq!(
            ctx.accounts.vault.authority,
            ctx.accounts.current_authority.key(),
            VaultError::Unauthorized
        );

        ctx.accounts.vault.authority = new_authority;
        Ok(())
    }

    pub fn set_authority_secure(
        ctx: Context<SetAuthoritySecure>,
        new_authority: Pubkey,
    ) -> Result<()> {
        // ✅ Secure:
        // - authority must be a Signer
        // - has_one ties vault.authority to the signer pubkey
        ctx.accounts.vault.authority = new_authority;
        Ok(())
    }
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAuthorityVulnerable<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    /// CHECK: intentionally unsafe for the example (not a signer)
    pub current_authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetAuthoritySecure<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    pub authority: Signer<'info>,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
}
