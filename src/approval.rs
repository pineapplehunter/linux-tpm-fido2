use std::io::{self, Write};

use crate::session;

pub fn approve(prompt: &str, session: &session::SessionContext) -> bool {
    let mut stdout = io::stdout();
    if write!(
        stdout,
        "[{session}] {prompt}? [y/N] ",
        session = session.describe()
    )
    .and_then(|_| stdout.flush())
    .is_err()
    {
        return false;
    }

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes")
}
