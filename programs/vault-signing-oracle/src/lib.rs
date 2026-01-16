use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;

declare_id!("5AsYzhPMktSi3K3eniimDhRhwHQnMRznAVCkXRyzwRSg");

#[program]
pub mod vault_signing_oracle {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.vault.authority = ctx.accounts.authority.key();
        ctx.accounts.vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // Anyone can deposit SOL into the vault PDA; funds come from depositor signer.
        let ix = system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &ctx.accounts.vault.key(),
            amount,
        );

        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        Ok(())
    }

    pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    require!(amount > 0, VaultError::InvalidAmount);

    // ❌ Vulnerable: "Signing Oracle"
    // Program moves lamports from the vault PDA to ANY recipient chosen by caller.
    // Anyone can call this and drain the vault.

    let vault_info = ctx.accounts.vault.to_account_info();
    let recipient_info = ctx.accounts.recipient.to_account_info();

    let vault_lamports = vault_info.lamports();
    require!(vault_lamports >= amount, VaultError::VaultInsufficientLamports);

    let recipient_lamports = recipient_info.lamports();

    **vault_info.try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(VaultError::MathOverflow)?;

    **recipient_info.try_borrow_mut_lamports()? = recipient_lamports
        .checked_add(amount)
        .ok_or(VaultError::MathOverflow)?;

    Ok(())
}


    pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    require!(amount > 0, VaultError::InvalidAmount);

    // ✅ Secure:
    // 1) Authority must SIGN (account constraint + signer)
    // 2) Recipient must be exactly the authority (so attacker can't redirect funds)
    require_keys_eq!(
        ctx.accounts.recipient.key(),
        ctx.accounts.authority.key(),
        VaultError::BadRecipient
    );

    let vault_info = ctx.accounts.vault.to_account_info();
    let recipient_info = ctx.accounts.recipient.to_account_info();

    let vault_lamports = vault_info.lamports();
    require!(vault_lamports >= amount, VaultError::VaultInsufficientLamports);

    let recipient_lamports = recipient_info.lamports();

    **vault_info.try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(VaultError::MathOverflow)?;

    **recipient_info.try_borrow_mut_lamports()? = recipient_lamports
        .checked_add(amount)
        .ok_or(VaultError::MathOverflow)?;

    Ok(())
}

}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 1,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    /// CHECK: recipient can be any account (this is the bug)
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    // Anyone can call this (attacker signs as caller)
    pub caller: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(
        mut,
        has_one = authority,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: we enforce recipient == authority in-code
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum VaultError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Recipient must be the authority")]
    BadRecipient,
    #[msg("Vault does not have enough lamports")]
    VaultInsufficientLamports,
    #[msg("Math overflow/underflow")]
    MathOverflow,
}
