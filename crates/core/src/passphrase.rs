//! Парольная фраза: секрет, который никогда не попадает в логи/argv/env.

use secrecy::{ExposeSecret as _, SecretString};
use tokio::io::AsyncWriteExt as _;
use tokio::process::ChildStdin;

use crate::{Error, Result};

/// Парольная фраза.
///
/// Внутри — `secrecy::SecretString` с `zeroize` на Drop. Никаких
/// `.to_string()` / `.display()` / `tracing` — пароль остаётся только
/// в памяти и уходит во внешние процессы исключительно через stdin.
#[derive(Debug, Clone)]
pub struct Passphrase(SecretString);

impl Passphrase {
    /// Создать пароль из `SecretString`.
    pub fn new(raw: SecretString) -> Self {
        Self(raw)
    }

    /// Доступ к секрету как к строке.
    ///
    /// Использовать только для передачи во внешний процесс через stdin
    /// или D-Bus; не для логирования, не для argv/env.
    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    /// Записать пароль в stdin дочернего процесса.
    ///
    /// Pipe должен быть настроен вызывающим при создании `Command`
    /// (`.stdin(Stdio::piped())`). После записи закрываем stdin,
    /// чтобы процесс увидел EOF.
    pub async fn write_to_stdin(&self, stdin: &mut ChildStdin) -> Result<()> {
        stdin
            .write_all(self.as_str().as_bytes())
            .await
            .map_err(Error::Io)?;
        stdin.shutdown().await.map_err(Error::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn passphrase_exposes_secret() {
        let p = Passphrase::new(SecretString::from("secret-phrase"));
        assert_eq!(p.as_str(), "secret-phrase");
    }
}
