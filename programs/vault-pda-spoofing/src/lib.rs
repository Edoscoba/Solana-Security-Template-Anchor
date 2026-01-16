use anchor_lang::prelude::*;

declare_id!("6PuAoUiJhy2eQ9YvkB5gogqPcQd28tcvuYsUSR9UJhLx");

#[program]
pub mod vault_pda_spoofing {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
