use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;

declare_id!("7PTR49svEPiHgnRQUfJ2wSYkP3MCiord6U7NWHAHKkzB");

#[program]
pub mod vault_unchecked_math {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        ctx.accounts.vault.bump = ctx.bumps.vault;
        ctx.accounts.vault.balance = 0;
        Ok(())
    }

    pub fn init_user(ctx: Context<InitUser>) -> Result<()> {
        ctx.accounts.user_credit.bump = ctx.bumps.user_credit;
        ctx.accounts.user_credit.credits = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // Transfer SOL from user -> vault PDA
        let ix = system_instruction::transfer(
            &ctx.accounts.user.key(),
            &ctx.accounts.vault.key(),
            amount,
        );

        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.user.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        // Update accounting using checked math
        let vault = &mut ctx.accounts.vault;
        let credit = &mut ctx.accounts.user_credit;

        vault.balance = vault
            .balance
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        credit.credits = credit
            .credits
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }

    pub fn withdraw_vulnerable(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        let vault = &mut ctx.accounts.vault;
        let credit = &mut ctx.accounts.user_credit;

        // ❌ Vulnerable:
        // Using wrapping_sub converts an underflow into a gigantic number.
        // Example: credits=0, amount=1 => remaining = 2^64 - 1
        //
        // Then checking `remaining >= 0` is meaningless for u64 (always true).
        // Result: users can withdraw even when credits < amount.
        let remaining_credits = credit.credits.wrapping_sub(amount);
        require!(remaining_credits >= 0, VaultError::InsufficientCredits);

        let remaining_vault = vault.balance.wrapping_sub(amount);
        require!(remaining_vault >= 0, VaultError::InsufficientVaultBalance);

        credit.credits = remaining_credits;
        vault.balance = remaining_vault;

        // Transfer lamports from vault PDA -> user
        let vault_info = vault.to_account_info();
        let user_info = ctx.accounts.user.to_account_info();

        let vault_lamports = vault_info.lamports();
        require!(vault_lamports >= amount, VaultError::VaultInsufficientLamports);

        let user_lamports = user_info.lamports();

        **vault_info.try_borrow_mut_lamports()? = vault_lamports
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        **user_info.try_borrow_mut_lamports()? = user_lamports
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }

    pub fn withdraw_secure(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        let vault = &mut ctx.accounts.vault;
        let credit = &mut ctx.accounts.user_credit;

        // ✅ Secure:
        // Compare first, then use checked math.
        require!(credit.credits >= amount, VaultError::InsufficientCredits);
        require!(vault.balance >= amount, VaultError::InsufficientVaultBalance);

        credit.credits = credit
            .credits
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        let vault_info = vault.to_account_info();
        let user_info = ctx.accounts.user.to_account_info();

        let vault_lamports = vault_info.lamports();
        require!(vault_lamports >= amount, VaultError::VaultInsufficientLamports);

        let user_lamports = user_info.lamports();

        **vault_info.try_borrow_mut_lamports()? = vault_lamports
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        **user_info.try_borrow_mut_lamports()? = user_lamports
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

#[account]
pub struct UserCredit {
    pub bump: u8,
    pub credits: u64,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 1 + 8,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = user,
        space = 8 + 1 + 8,
        seeds = [b"credit", vault.key().as_ref(), user.key().as_ref()],
        bump
    )]
    pub user_credit: Account<'info, UserCredit>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"credit", vault.key().as_ref(), user.key().as_ref()],
        bump = user_credit.bump
    )]
    pub user_credit: Account<'info, UserCredit>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"credit", vault.key().as_ref(), user.key().as_ref()],
        bump = user_credit.bump
    )]
    pub user_credit: Account<'info, UserCredit>,

    #[account(mut)]
    pub user: Signer<'info>,
}

#[error_code]
pub enum VaultError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient credits")]
    InsufficientCredits,
    #[msg("Vault internal balance too low")]
    InsufficientVaultBalance,
    #[msg("Vault does not have enough lamports")]
    VaultInsufficientLamports,
    #[msg("Math overflow/underflow")]
    MathOverflow,
}
