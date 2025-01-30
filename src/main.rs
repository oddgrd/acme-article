use std::{collections::HashMap, time::Duration};

use anyhow::{bail, Context};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::any,
    Router,
};
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // This is how we would create the account in production.
    // let account = NewAccount {
    //     // Optionally add a list of contact URIs (like mailto:info@your-domain.com).
    //     contact: &[],
    //     terms_of_service_agreed: true,
    //     only_return_existing: false,
    // };

    // let (account, _credentials) = Account::create(&account, LetsEncrypt::Staging.url(), None)
    // .await
    // .context("failed to create acme account")?;

    let account = local_account().await?;

    tracing::info!("account created");

    let domain = "my-domain.com";

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[Identifier::Dns(domain.to_string())],
        })
        .await
        .context("failed to order certificate")?;

    let authorizations = order
        .authorizations()
        .await
        .context("failed to retrieve order authorizations")?;

    // There should only ever be 1 authorization as we only provided 1 domain above.
    let authorization = authorizations
        .first()
        .context("there should be one authorization")?;

    if !matches!(authorization.status, AuthorizationStatus::Pending) {
        bail!("order should be pending");
    }

    let challenge = authorization
        .challenges
        .iter()
        .find(|c| c.r#type == ChallengeType::Http01)
        .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;

    let challenges = HashMap::from([(
        challenge.token.clone(),
        order.key_authorization(challenge).as_str().to_string(),
    )]);

    tracing::info!("challenges: {:?}", challenges);

    let acme_router = acme_router(challenges);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5002").await.unwrap();

    // Start the Axum server as a background task, so it's running while we complete the challenge
    // in the next steps.
    tokio::task::spawn(async move { axum::serve(listener, acme_router).await.unwrap() });

    tracing::info!("Serving ACME handler at: 0.0.0.0:5002");

    order
        .set_challenge_ready(&challenge.url)
        .await
        .context("failed to notify server that challenge is ready")?;

    // We now need to wait until the order reaches an end-state. We refresh the order in a loop,
    // with exponential backoff, until the order is either ready or invalid (for example if our
    // challenge server responded with the wrong key authorization).
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        tokio::time::sleep(delay).await;
        let state = order.refresh().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            tracing::info!("order state: {:#?}", state);
            break;
        }

        delay *= 2;
        tries += 1;
        if tries < 15 {
            tracing::info!(?state, tries, "order is not ready, waiting {delay:?}");
        } else {
            tracing::error!(
                tries,
                "timed out before order reached ready state: {state:#?}"
            );
            bail!("timed out before order reached ready state");
        }
    }

    let state = order.state();
    if state.status != OrderStatus::Ready {
        bail!("unexpected order status: {:?}", state.status);
    }

    tracing::info!(?state, "challenge completed");

    // Create a CSR for our domain.
    let mut params = CertificateParams::new(vec![domain.to_owned()])?;
    params.distinguished_name = DistinguishedName::new();
    let private_key = KeyPair::generate()?;
    let signing_request = params.serialize_request(&private_key)?;

    // DER encode the CSR and use it to request the certificate.
    order
        .finalize(signing_request.der())
        .await
        .context("failed to finalize order")?;

    // Poll for certificate, do this for a few rounds.
    let mut cert_chain_pem: Option<String> = None;
    let mut retries = 5;
    while cert_chain_pem.is_none() && retries > 0 {
        cert_chain_pem = order
            .certificate()
            .await
            .context("failed to get the certificate for order")?;
        retries -= 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let Some(chain) = cert_chain_pem else {
        bail!("failed to get certificate for order before timeout");
    };

    tracing::info!("certificate chain:\n\n{}", chain);
    tracing::info!("private key:\n\n{}", private_key.serialize_pem());
    Ok(())
}

/// Respond to HTTP-01 challenges by extracting the token from the path of the request, and then
/// using the token to look up the matching key authorization in our internal state.
pub async fn http01_challenge(
    State(challenges): State<HashMap<String, String>>,
    Path(token): Path<String>,
) -> Result<String, StatusCode> {
    tracing::info!(%token, "received HTTP-01 ACME challenge");

    if let Some(key_auth) = challenges.get(&token) {
        Ok({
            tracing::info!(%key_auth, "responding to ACME challenge");
            key_auth.clone()
        })
    } else {
        tracing::warn!(%token, "didn't find acme challenge");
        Err(StatusCode::NOT_FOUND)
    }
}

/// Set up a simple acme server to respond to http01 challenges.
pub fn acme_router(challenges: HashMap<String, String>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{*rest}", any(http01_challenge))
        .with_state(challenges)
}

async fn local_account() -> anyhow::Result<Account> {
    let http_client = client_with_custom_ca_cert();
    let account = create_account(
        http_client.clone(),
        "fake@email.com",
        Some("https://localhost:14000/dir".to_string()),
    )
    .await
    .expect("creating acme account");

    Ok(account)
}

/// Only used for local run with Pebble.
/// See <https://github.com/letsencrypt/pebble?tab=readme-ov-file#avoiding-client-https-errors> for
/// why we need to add the pebble cert to the client root certificates.
fn client_with_custom_ca_cert() -> Box<Client<HttpsConnector<HttpConnector>, Full<Bytes>>> {
    use hyper_util::rt::TokioExecutor;
    use rustls::{crypto::aws_lc_rs, RootCertStore};

    aws_lc_rs::default_provider().install_default().unwrap();

    let f = std::fs::File::open("pebble.minica.pem").unwrap();
    let mut ca = std::io::BufReader::new(f);
    let certs = rustls_pemfile::certs(&mut ca)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certs);
    // TLS client config using the custom CA store for lookups
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    let client = Client::builder(TokioExecutor::new()).build(https);

    Box::new(client)
}

/// Create a new ACME account that can be restored by using the deserialization
/// of the returned JSON into a [`instant_acme::AccountCredentials`]
async fn create_account(
    http_client: Box<Client<HttpsConnector<HttpConnector>, Full<Bytes>>>,
    email: &str,
    acme_server: Option<String>,
) -> anyhow::Result<Account> {
    use instant_acme::{LetsEncrypt, NewAccount};
    let acme_server = acme_server.unwrap_or_else(|| LetsEncrypt::Production.url().to_string());

    let account: NewAccount = NewAccount {
        contact: &[&format!("mailto:{email}")],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    // We only a custom Http client with a specific TLS setup when using Pebble
    let account = Account::create_with_http(&account, &acme_server, None, http_client)
        .await
        .context("failed to create account with custom http client")?
        .0;

    Ok(account)
}
