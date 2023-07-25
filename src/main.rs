
use chrono::{Duration, Utc};
// use ed25519_dalek::{Keypair, Signature, Signer};

use siopv2::{
    claims::{ClaimRequests, ClaimValue, IndividualClaimRequest,StandardClaimsValues},
    request::ResponseType,
    Provider, Registration, RelyingParty, RequestUrl, AuthorizationResponse, Scope, AuthorizationRequest, StandardClaimsRequests, Subject, Validator, IdTokenBuilder, key_method::KeySubject,
};

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{sync::Arc, convert::TryInto};
use anyhow::Result;
use derivative::{self, Derivative};

use did_url::DID;
use did_key::*;


#[derive(Derivative)]
#[derivative(Default)]
pub struct TestSubject {
    #[derivative(Default(value = "did_url::DID::parse(\"did:test:123\").unwrap()"))]
    pub did: did_url::DID,
    pub key_id: String,
}

impl TestSubject {
    pub fn new(did: String, key_id: String) -> Result<Self> {
        Ok(TestSubject {
            did: did_url::DID::parse(did)?,
            key_id,
        })
    }
}

#[tokio::main]
  async fn main() {
    // let my_did = DID::parse("did:example:alice").unwrap();
    // let subject: TestSubject = TestSubject::new( "did:example:alice".to_string(),"did:example:alice".to_string()).unwrap();
    // Create a new subject.
    // let subject: KeySubject = KeySubject::new();
    // let seed =generate::<Ed25519KeyPair>(Some(
    //     "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
    // ));

    // let seed = generate::<Ed25519KeyPair>(None);
    // let did_doc = seed.get_did_document(Config::default());
    // let doc_json = serde_json::to_string(&did_doc).unwrap();

    // println!("public_key_bytes : {:?}", seed.public_key_bytes());
    // println!("private_key_bytes : {:?}", seed.private_key_bytes());

    let public_key_data: [u8; 32] = [194, 250, 72, 132, 232, 162, 51, 63, 135, 164, 239, 234, 103, 110, 252, 94, 67, 104, 84, 180, 34, 25, 233, 66, 223, 41, 135, 183, 56, 43, 243, 24];
    let private_key_data: [u8; 32] = [117, 247, 48, 71, 65, 77, 98, 63, 173, 84, 130, 128, 68, 95, 201, 238, 67, 129, 209, 108, 97, 227, 28, 138, 49, 130, 247, 21, 18, 135, 219, 12];
    let seed = from_existing_key::<Ed25519KeyPair>(&public_key_data, Some(&private_key_data));


    let subject: KeySubject = KeySubject::from_keypair(seed);


    // Create a new provider.
    let provider = Provider::new(subject).await.unwrap();
    let did = provider.subject.did().unwrap();


    println!("did : {:?}", did);

    let request_url = "\
        siopv2://idtoken?\
            scope=openid\
            &response_type=id_token\
            &client_id=did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF\
            &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
            &response_mode=post\
            &registration=%7B%22subject_syntax_types_supported%22%3A\
            %5B%22did%3Akey%22%5D%2C%0A%20%20%20%20\
            %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
            &nonce=n-0S6_WzA2Mj\
        ";

    // let request: AuthorizationRequest = RequestUrl::builder()
    //     .response_type(ResponseType::IdToken)
    //     .client_id("did:mymethod:relyingparty".to_string())
    //     .scope(Scope::openid())
    //     .redirect_uri(format!("app.com/redirect_uri"))
    //     .response_mode("post".to_string())
    //     .registration(
    //         Registration::default()
    //             .with_subject_syntax_types_supported(vec!["did:mymethod".to_string()])
    //             .with_id_token_signing_alg_values_supported(vec!["EdDSA".to_string()]),
    //     )
    //     .claims(ClaimRequests {
    //         id_token: Some(StandardClaims {
    //             name: Some(IndividualClaimRequest::default()),
    //             ..Default::default()
    //         }),
    //         ..Default::default()
    //     })
    //     .exp((Utc::now() + Duration::minutes(10)).timestamp())
    //     .nonce("n-0S6_WzA2Mj".to_string())
    //     .build()
    //     .and_then(TryInto::try_into)
    //     .unwrap();


    let request = provider.validate_request(request_url.parse().unwrap()).await.unwrap();

    let response = provider
        .generate_response(
            request,
            StandardClaimsValues {
                name: Some("Jane Doe".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        println!("AuthorizationRequest: {:?}", response.id_token());
    
}