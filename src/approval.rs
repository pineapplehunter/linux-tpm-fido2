use std::io::{self, Write};

pub fn approve(prompt: &str) -> bool {
    let mut stdout = io::stdout();
    if write!(stdout, "{prompt}? [y/N] ")
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
