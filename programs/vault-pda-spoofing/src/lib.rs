use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;

declare_id!("6PuAoUiJhy2eQ9YvkB5gogqPcQd28tcvuYsUSR9UJhLx");

#[program]
pub mod vault_pda_spoofing {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // Store the PDA bump so we can validate bump later.
        ctx.accounts.vault.bump = ctx.bumps.vault;
        ctx.accounts.vault.balance = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // Transfer SOL from the signer to the vault PDA.
        let ix = system_instruction::transfer(
            &ctx.accounts.authority.key(),
            &ctx.accounts.vault.key(),
            amount,
        );

       anchor_lang::solana_program::program::invoke(

            &ix,
            &[
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        // Track deposited amount in program state (so we don't accidentally drain rent).
        ctx.accounts.vault.balance = ctx
            .accounts
            .vault
            .balance
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }

    pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // ❌ Vulnerable:
        // We do NOT verify that `vault` is the PDA derived from `authority`.
        //
        // That means ANYONE can pass SOMEONE ELSE'S vault PDA here and withdraw
        // funds to themselves, because the program owns the vault account and can move its lamports.
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientFunds);

        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        let vault_info = vault.to_account_info();
        let authority_info = ctx.accounts.authority.to_account_info();

        let vault_lamports = vault_info.lamports();
        let authority_lamports = authority_info.lamports();

        **vault_info.try_borrow_mut_lamports()? = vault_lamports
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        **authority_info.try_borrow_mut_lamports()? = authority_lamports
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }

    pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // ✅ Secure:
        // The account constraint below enforces:
        // vault.key() == PDA("vault", authority.key())
        // so you cannot pass someone else's vault.
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientFunds);

        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        let vault_info = vault.to_account_info();
        let authority_info = ctx.accounts.authority.to_account_info();

        let vault_lamports = vault_info.lamports();
        let authority_lamports = authority_info.lamports();

        **vault_info.try_borrow_mut_lamports()? = vault_lamports
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        **authority_info.try_borrow_mut_lamports()? = authority_lamports
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }
}

#[account]
pub struct Vault {
    pub bump: u8,
    pub balance: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 1 + 8,
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
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[error_code]
pub enum VaultError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Math overflow/underflow")]
    MathOverflow,
}
