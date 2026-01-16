use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;

declare_id!("2S1KrvmHnCG2bDdYAihwjD9SxZUUuiwuY8stTnwPoPek");

#[program]
pub mod payment_legit {
    use super::*;

    pub fn collect_payment(ctx: Context<CollectPayment>, amount: u64) -> Result<()> {
        require!(amount > 0, PaymentError::InvalidAmount);

        // Transfer SOL from payer -> vault using the real System Program
        let ix = system_instruction::transfer(
            &ctx.accounts.payer.key(),
            &ctx.accounts.vault.key(),
            amount,
        );

        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.payer.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct CollectPayment<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: destination vault can be any account (including program-owned PDA)
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum PaymentError {
    #[msg("Invalid amount")]
    InvalidAmount,
}
