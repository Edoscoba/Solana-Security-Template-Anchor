use anchor_lang::prelude::*;

declare_id!("tJ3RVWjt66opLJdVJXBeEAQuKbwbDQq5fKg3cTxod1o");

#[program]
pub mod vault_cpi_injection {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        ctx.accounts.vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn init_user(ctx: Context<InitUser>) -> Result<()> {
        ctx.accounts.user_credit.bump = ctx.bumps.user_credit;
        ctx.accounts.user_credit.credits = 0;
        Ok(())
    }

    pub fn deposit_vulnerable(ctx: Context<DepositVulnerable>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // ❌ Vulnerable:
        // We CPI to a "payment program" provided by the user WITHOUT PINNING IT.
        // Attacker can pass a malicious program that returns Ok(()) but doesn't transfer SOL.
        let cpi_program = ctx.accounts.payment_program.to_account_info();
        let cpi_accounts = payment_legit::cpi::accounts::CollectPayment {
            payer: ctx.accounts.user.to_account_info(),
            vault: ctx.accounts.vault.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        };

        payment_legit::cpi::collect_payment(
            CpiContext::new(cpi_program, cpi_accounts),
            amount,
        )?;

        // Program assumes CPI collected payment. If CPI target was malicious, this is now wrong.
        ctx.accounts.user_credit.credits = ctx.accounts.user_credit.credits
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }

    pub fn deposit_secure(ctx: Context<DepositSecure>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        // ✅ Secure:
        // Here, the payment program is typed as Program<PaymentLegit> which pins the program id.
        let cpi_program = ctx.accounts.payment_program.to_account_info();
        let cpi_accounts = payment_legit::cpi::accounts::CollectPayment {
            payer: ctx.accounts.user.to_account_info(),
            vault: ctx.accounts.vault.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        };

        payment_legit::cpi::collect_payment(
            CpiContext::new(cpi_program, cpi_accounts),
            amount,
        )?;

        ctx.accounts.user_credit.credits = ctx.accounts.user_credit.credits
            .checked_add(amount)
            .ok_or(VaultError::MathOverflow)?;

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        require!(
            ctx.accounts.user_credit.credits >= amount,
            VaultError::InsufficientCredits
        );

        // Reduce credits first
        ctx.accounts.user_credit.credits = ctx.accounts.user_credit.credits
            .checked_sub(amount)
            .ok_or(VaultError::MathOverflow)?;

        // Transfer lamports from vault -> user
        let vault_info = ctx.accounts.vault.to_account_info();
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
        space = 8 + 1,
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
pub struct DepositVulnerable<'info> {
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

    /// CHECK: ❌ Vulnerable: user supplies CPI target program id
    pub payment_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositSecure<'info> {
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

    // ✅ Pins the CPI target to the legit payment program id
    pub payment_program: Program<'info, payment_legit::program::PaymentLegit>,

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
    #[msg("Math overflow/underflow")]
    MathOverflow,
    #[msg("Insufficient credits")]
    InsufficientCredits,
    #[msg("Vault does not have enough lamports")]
    VaultInsufficientLamports,
}
