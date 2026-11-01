//! Anvil end-to-end tests for the on-chain smart-account path.
//!
//! Opt-in suite: set `SIWX_E2E_ANVIL=1` (needs `anvil` from Foundry).
#![allow(
    unused_crate_dependencies,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::tests_outside_test_module,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    reason = "e2e test helpers may panic/index"
)]
#![cfg(feature = "rpc")]

use alloy::network::{Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use serde_json::Value;
use siwx::Namespace;
use siwx::evm::Evm;
/// ERC-6492 detection suffix: `0x6492` repeated 16 times.
const MAGIC: [u8; 32] =
    alloy::hex!("6492649264926492649264926492649264926492649264926492649264926492");

fn enabled() -> bool {
    std::env::var("SIWX_E2E_ANVIL").is_ok_and(|v| v == "1")
}

/// Solidity fixtures live in `vectors/evm/e2e/Owner1271.sol` and
/// `vectors/evm/e2e/Factory.sol` (compiled to `contracts.json`).
fn contracts() -> Value {
    let root = format!("{}/../../vectors", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(
        &std::fs::read_to_string(format!("{root}/evm/e2e/contracts.json")).expect("read"),
    )
    .expect("json")
}

fn code(name: &str) -> Vec<u8> {
    let c = contracts();
    let h = c["contracts"][name]["creationBytecode"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x")
        .to_owned();
    let h = h.as_str();
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

sol! {
    interface IERC1271Factory {
        function deploy(address owner, bytes32 salt) external returns (address);
    }

}

struct Rig {
    anvil: AnvilInstance,
    provider: DynProvider,
    owner: Address,
}

fn rig() -> Rig {
    // Random high port avoids clashes with stale local anvils.
    let port = 20_000 + (std::process::id() % 30_000) as u16;
    let anvil = Anvil::new().port(port).spawn();
    let key: PrivateKeySigner = anvil.keys()[0].clone().into();
    let wallet = EthereumWallet::from(key);
    let owner_addr = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);
    let provider: DynProvider = Provider::erased(
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(anvil.endpoint_url()),
    );
    Rig {
        anvil,
        provider,
        owner: owner_addr,
    }
}

async fn deploy(provider: &DynProvider, bytecode: Vec<u8>) -> Address {
    let tx = provider
        .send_transaction(
            <Ethereum as alloy::network::Network>::TransactionRequest::default()
                .with_deploy_code(Bytes::from(bytecode)),
        )
        .await
        .unwrap();
    let receipt = tx.get_receipt().await.unwrap();
    receipt.contract_address.unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn message_for(address: &str) -> siwx::Message {
    siwx::Message::new(siwx::MessageFields {
        domain: "service.org".into(),
        address: address.into(),
        uri: "https://service.org/login".into(),
        version: "1".into(),
        chain_id: "31337".into(),
        nonce: "12341234".into(),
        issued_at: "2022-03-17T12:45:13.610Z".into(),
        ..Default::default()
    })
    .unwrap()
}

/// ERC-6492 signature: abi.encode(factory, deployCalldata, sig) + MAGIC.
fn wrap_6492(factory: Address, call: Vec<u8>, sig: &[u8]) -> Vec<u8> {
    // abi.encode(factory, calldata, signature) — params encoding (no tuple
    // offset wrapper).
    let mut w = (factory, Bytes::from(call), Bytes::from(sig.to_vec())).abi_encode_params();
    w.extend_from_slice(&MAGIC);
    w
}

#[test]
fn anvil_e2e() {
    if !enabled() {
        eprintln!("SIWX_E2E_ANVIL!=1 — skipping anvil e2e");
        return;
    }
    rt().block_on(async {
        let rig = rig();
        let owner = rig.owner;

        // Deployed Owner1271 owned by the signer.
        let mut init = code("Owner1271");
        init.extend_from_slice(&owner.abi_encode());
        let contract = deploy(&rig.provider, init.clone()).await;

        // Owner's personal_sign over the SIWE text.
        let text = Evm::new()
            .format(&message_for(&contract.to_string()))
            .unwrap();
        let signer: PrivateKeySigner = rig.anvil.keys()[0].clone().into();
        let sig = signer.sign_message(text.as_bytes()).await.unwrap();
        let msg = Evm::new().parse(text.as_bytes()).unwrap();

        let evm = Evm::new().with_provider(31337, rig.provider.clone());
        evm.verify(&msg, text.as_bytes(), sig.as_bytes().as_slice())
            .await
            .expect("deployed 1271 should verify");

        // Wrong-owner contract must fail.
        let wrong = message_for(&contract.to_string());
        let text2 = Evm::new()
            .format(&wrong)
            .unwrap()
            .replace("12341234", "87654321");
        let msg2 = Evm::new().parse(text2.as_bytes()).unwrap();
        let wrong_err = evm
            .verify(&msg2, text2.as_bytes(), sig.as_bytes().as_slice())
            .await
            .expect_err("wrong owner must fail");
        assert!(
            matches!(wrong_err, siwx::Error::VerificationFailed),
            "got {wrong_err:?}"
        );

        // Counterfactual: Factory.deploy(owner, salt) never called; the
        // 6492 wrapper makes the validator deploy + check.
        let factory = deploy(&rig.provider, code("Factory")).await;
        let salt = B256::from(U256::from(42u64));
        // CREATE2: keccak(0xff ‖ factory ‖ salt ‖ keccak(initcode))[12..].
        let create2 = Address::from_slice(
            &keccak256(
                [
                    &[0xffu8][..],
                    factory.as_slice(),
                    salt.as_slice(),
                    keccak256(init.as_slice()).as_slice(),
                ]
                .concat(),
            )[12..],
        );
        let call = IERC1271Factory::deployCall { owner, salt }.abi_encode();
        let cf_text = Evm::new()
            .format(&message_for(&create2.to_checksum(None)))
            .unwrap();
        let cf_sig = signer.sign_message(cf_text.as_bytes()).await.unwrap();
        let wrapped = wrap_6492(factory, call.clone(), cf_sig.as_bytes().as_slice());
        let cf_msg = Evm::new().parse(cf_text.as_bytes()).unwrap();
        evm.verify(&cf_msg, cf_text.as_bytes(), &wrapped)
            .await
            .expect("counterfactual 6492 must verify");

        // Provider bound to chain 1 while anvil reports 31337 → Mismatch.
        let evm1 = Evm::new().with_provider(1, rig.provider.clone());
        let text_on1 = text.replace("Chain ID: 31337", "Chain ID: 1");
        let msg_on1 = Evm::new().parse(text_on1.as_bytes()).unwrap();
        let chain_err = evm1
            .verify(&msg_on1, text_on1.as_bytes(), sig.as_bytes().as_slice())
            .await
            .expect_err("wrong-chain provider must mismatch");
        assert!(
            matches!(chain_err, siwx::Error::Mismatch { .. }),
            "got {chain_err:?}"
        );

        // EOA path stays offline.
        let eoa_text = Evm::new()
            .format(&message_for(&owner.to_checksum(None)))
            .unwrap();
        let eoa_sig = signer.sign_message(eoa_text.as_bytes()).await.unwrap();
        let eoa_msg = Evm::new().parse(eoa_text.as_bytes()).unwrap();
        evm.verify(&eoa_msg, eoa_text.as_bytes(), eoa_sig.as_bytes().as_slice())
            .await
            .expect("EOA offline verify");
    });
}
