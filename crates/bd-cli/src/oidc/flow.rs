//! Sign-in with a provider: the authorization URL, code exchange and the device flow.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bd_core::{Error, Result};
use serde_json::Value;

use super::*;

impl Oidc {
    /// Where the browser signs in: the code comes back to `redirect_uri`
    /// with `state`, its ID token carries `nonce`, and its token is given
    /// only with the PKCE verifier whose S256 challenge is `challenge`.
    pub fn authorization_url(
        &self,
        md: &Metadata,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> String {
        let scope = self.scopes.join(" ");
        let query = [
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("scope", scope.as_str()),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ];
        let mode = [("response_mode", "form_post")];
        let query: Vec<(&str, &str)> = query.iter().chain(mode.iter().filter(|_| self.form_post)).copied().collect();
        let sep = if md.authorization_endpoint.contains('?') { '&' } else { '?' };
        format!("{}{sep}{}", md.authorization_endpoint, crate::oauth_server::form::encode(&query))
    }

    /// The ID token's verified claims for `code`, which came back to
    /// `redirect_uri` (`verifier` is its PKCE verifier, `nonce` the one the
    /// sign-in sent).
    pub fn sign_in(
        &self,
        md: &Metadata,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<Claims> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ];
        let answer = self.token(md, &form)?;
        if let Some(error) = answer["error"].as_str() {
            return Err(Error::invalid(format!("{} refused the sign-in's code ({})", self.label, error_code(error))));
        }
        let Some(id_token) = answer["id_token"].as_str() else {
            return Err(self.unwell("its token endpoint gave no ID token".into()));
        };
        self.verify(md, id_token, Some(nonce))
    }

    /// POST `form` to the token endpoint, as this client: its JSON answer,
    /// or `{"error": ...}` when it refused.
    pub fn token(&self, md: &Metadata, form: &[(&str, &str)]) -> Result<Value> {
        self.post(md, &md.token_endpoint, form)
    }

    /// Start a sign-in from the command line (RFC 8628): the provider's
    /// answer (`device_code`, `user_code`, `verification_uri`, ...), or
    /// `Invalid` if it has no device flow.
    pub fn device(&self, md: &Metadata) -> Result<Value> {
        let Some(endpoint) = &md.device_authorization_endpoint else {
            return Err(Error::invalid(format!(
                "{} does not offer sign-in from the command line (the device flow); sign in from an MCP client in a \
                 browser instead",
                self.label
            )));
        };
        let scope = self.scopes.join(" ");
        let answer = self.post(md, endpoint, &[("scope", &scope)])?;
        if let Some(error) = answer["error"].as_str() {
            return Err(self.unwell(format!("its device endpoint refused: {}", error_code(error))));
        }
        Ok(answer)
    }

    /// POST `form` to `url` as this client (its ID, and its secret as the
    /// provider takes it): the JSON answer, or `{"error": ...}`.
    fn post(&self, md: &Metadata, url: &str, form: &[(&str, &str)]) -> Result<Value> {
        let mut form: Vec<(&str, &str)> = form.to_vec();
        form.push(("client_id", &self.client_id));
        let mut request = agent().post(url).header("accept", "application/json");
        let secret = self.secret()?;
        match (&secret, md.basic_auth) {
            (Some(Secret(secret)), true) => {
                let pair = format!("{}:{}", form_encode(&self.client_id), form_encode(secret));
                request = request.header("authorization", format!("Basic {}", STANDARD.encode(pair)));
            }
            (Some(Secret(secret)), false) => form.push(("client_secret", secret)),
            (None, _) => {}
        }
        let sent = request.send_form(form.iter().copied());
        let mut response = sent.map_err(|e| self.unreachable(url, e))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_string()
            .map_err(|e| self.unreachable(url, e))?;
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(error) = body["error"].as_str() {
            return Ok(serde_json::json!({ "error": error }));
        }
        if status != 200 {
            return Err(self.unwell(format!("{url} answered HTTP {status}")));
        }
        Ok(body)
    }
}
