use actix_web::{web, App, HttpServer, Responder, HttpRequest, HttpResponse, http::{header::{self, ContentType}, StatusCode, Error}};
use deflate::deflate_bytes;
use rand::{rngs::ThreadRng, RngCore};
use sha2::{Digest};

async fn greet(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", name)
}

fn createAuthReq() -> HttpResponse {
    let mut rand = ThreadRng::default();
    let mut buf: [u8; 32] = [0; 32];
    rand.fill_bytes(&mut buf);

    let mut hasher = sha2::Sha256::new();
    hasher.update(&buf);
    let hash = hasher.finalize();

    let auth_req = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest
  xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  AssertionConsumerServiceURL="https://test.ruimo.com/saml/acs"
  ID="_{}"
  IssueInstant="{:?}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://test.ruimo.com</saml2:Issuer>
</saml2p:AuthnRequest>
"#,
    base64_url::encode(&hash),
    chrono::Utc::now());

//  let deflated = deflate_bytes(auth_req.as_bytes());
  let b64 = base64::encode(auth_req.as_bytes());
//  let req_url = format!("https://accounts.google.com/o/saml2/idp?idpid=C03sygdc7&SAMLRequst={}", urlencoding::encode(&b64).into_owned());

    HttpResponse::Ok().content_type(ContentType::html()).body(
        "<!DOCTYPE html><html><body>
            <p>Welcome to your TLS-secured homepage!</p>
        </body></html>",
    )
}

fn createAuthPostReq() -> HttpResponse {
    let mut rand = ThreadRng::default();
    let mut buf: [u8; 32] = [0; 32];
    rand.fill_bytes(&mut buf);

    let mut hasher = sha2::Sha256::new();
    hasher.update(&buf);
    let hash = hasher.finalize();
    let hash_str = base64_url::encode(&hash);

    let auth_req = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest
  xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  AssertionConsumerServiceURL="https://test.ruimo.com/saml/acs"
  ID="_{}"
  IssueInstant="{:?}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://test.ruimo.com</saml2:Issuer>
</saml2p:AuthnRequest>
"#,
    &hash_str,
    chrono::Utc::now());

  let b64 = base64::encode(auth_req.as_bytes());
//  let req_url = format!("https://accounts.google.com/o/saml2/idp?idpid=C03sygdc7&SAMLRequst={}", urlencoding::encode(&b64).into_owned());

    HttpResponse::Ok().content_type(ContentType::html()).body(
        format!(
            include_str!("authn_req_post.html"),
            idp_url = "https://accounts.google.com/o/saml2/idp?idpid=C03sygdc7",
            saml_request = b64,
            id = &hash_str
        )
    )
}

async fn secure(req: HttpRequest) -> impl Responder {
    createAuthPostReq()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .route("/", web::get().to(greet))
        .route("/secure", web::get().to(secure))
    })
    .bind("0.0.0.0:8084")?
    .run()
    .await
}
