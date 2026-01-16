use anchor_lang::prelude::*;

declare_id!("9cHbdhPtPzpsMkxmmLP3nsnicuewSneNQSkCw5JmbRBF");

#[program]
pub mod payment_evil {
    use super::*;

    pub fn collect_payment(_ctx: Context<CollectPayment>, _amount: u64) -> Result<()> {
        // 😈 EVIL BEHAVIOR:
        // Pretend payment was collected but do NOTHING.
        // Returning Ok(()) tricks the caller (vault) into thinking funds were received.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CollectPayment<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: vault passed in, but we ignore it
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}
