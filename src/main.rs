use std::str::FromStr;

use bdk::bitcoin::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::key::Secp256k1;
use bdk::bitcoin::{Address, Amount, Network};
use bdk::blockchain::EsploraBlockchain;
use bdk::database::MemoryDatabase;
use bdk::keys::bip39::{Language, Mnemonic};
use bdk::keys::{self, DerivableKey, DescriptorKey, GeneratedKey};
use bdk::keys::{ExtendedKey, GeneratableKey};
use bdk::miniscript::Tap;
use bdk::wallet::AddressIndex::New;
use wasm_bindgen_futures::spawn_local;
use web_sys::window;

use bdk::{esplora_client, SignOptions, SyncOptions, Wallet};
use leptos::{mount_to_body, view};
use log::info;

fn main() -> Result<(), bdk::Error> {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let blockchain = EsploraBlockchain::new("https://mutinynet.com/api/", 20);

    let (desc1, desc2) = get_descriptors();

    let wallet = Wallet::new(
        &desc1,
        Some(&desc2),
        Network::Signet,
        MemoryDatabase::default(),
    )?;

    let address_1 = wallet.get_address(New)?;

    spawn_local(async move {
        let client = esplora_client::Builder::new("https://mutinynet.com/api/")
            .build_async()
            .unwrap();

        wallet
            .sync(&blockchain, SyncOptions::default())
            .await
            .unwrap();
        let mut tx_builder = wallet.build_tx();

        let wallet_balance = wallet.get_balance().unwrap().confirmed.to_string().clone();

        mount_to_body(|| {
            view! {
            <p> {wallet_balance} </p>}
        });

        let faucet_address = Address::from_str("tb1qd28npep0s8frcm3y7dxqajkcy2m40eysplyr9v")
            .unwrap()
            .require_network(Network::Signet)
            .unwrap();

        tx_builder
            .add_recipient(faucet_address.script_pubkey(), 1000)
            .enable_rbf();

        let mut psbt = tx_builder.finish().unwrap();
        wallet.sign(&mut psbt.0, SignOptions::default()).unwrap();
        let tx = psbt.0.extract_tx();
        client.broadcast(&tx).await.unwrap();
        info!("Tx broadcasted! Txid: {}", tx.txid());
    });

    mount_to_body(move || {
        view! { <p> {address_1.to_string()} </p>
        }
    });

    Ok(())
}

fn get_descriptors() -> (String, String) {
    let secp = Secp256k1::new();

    let window = window().expect("no global `window` exists");
    let local_storage = window
        .local_storage()
        .expect("no local storage")
        .expect("local storage is not available");

    let mnemonic = if let Ok(Some(mnemonic)) = local_storage.get_item("mnemonic") {
        info!("Mnemonic: {}", mnemonic.to_string());
        mnemonic
    } else {
        let mnemonic: GeneratedKey<_, Tap> =
            Mnemonic::generate((keys::bip39::WordCount::Words12, Language::English)).unwrap();
        let mnemonic = mnemonic.to_string();
        let _ = local_storage.set("mnemonic", &mnemonic);
        info!("Mnemonic: {}", mnemonic);
        mnemonic
    };

    let mnemonic: Mnemonic = Mnemonic::from_str(&mnemonic).unwrap();

    let xkey: ExtendedKey = (mnemonic, None).into_extended_key().unwrap();
    let xprv: bdk::bitcoin::bip32::ExtendedPrivKey = xkey.into_xprv(Network::Signet).unwrap();
    let mut keys = Vec::new();

    for path in ["m/86h/0h/0h/0", "m/86h/0h/0h/1"] {
        let deriv_path: DerivationPath = DerivationPath::from_str(path).unwrap();
        let derived_xprv = &xprv.derive_priv(&secp, &deriv_path).unwrap();
        let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);
        let derived_xprv_desc_key: DescriptorKey<Tap> = derived_xprv
            .into_descriptor_key(Some(origin), DerivationPath::default())
            .unwrap();

        if let DescriptorKey::Secret(key, _, _) = &derived_xprv_desc_key {
            let mut desc = "tr(".to_string();
            desc.push_str(&key.to_string());
            desc.push(')');
            keys.push(desc);
        }
    }

    (keys[0].clone(), keys[1].clone())
}
