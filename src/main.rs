use std::str::FromStr;
use std::sync::Arc;

use bdk::bitcoin::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::key::Secp256k1;
use bdk::bitcoin::{Address, Network};
use bdk::blockchain::EsploraBlockchain;
use bdk::database::MemoryDatabase;
use bdk::keys::bip39::{Language, Mnemonic};
use bdk::keys::{self, DerivableKey, DescriptorKey, GeneratedKey};
use bdk::keys::{ExtendedKey, GeneratableKey};
use bdk::miniscript::Tap;
use bdk::wallet::AddressIndex::New;
use futures::lock::Mutex;
use wasm_bindgen_futures::spawn_local;
use web_sys::window;

use bdk::{esplora_client, SignOptions, SyncOptions, Wallet};
use leptos::*;
use log::info;

fn main() -> Result<(), bdk::Error> {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let (desc1, desc2) = get_descriptors();

    let wallet: Wallet<MemoryDatabase> = Wallet::new(
        &desc1,
        Some(&desc2),
        Network::Signet,
        MemoryDatabase::default(),
    )
    .unwrap();

    let wallet = Arc::new(Mutex::new(wallet));
    let wallet_1 = wallet.clone();
    let wallet_2 = wallet.clone();

    mount_to_body(move || {
        view! {
            <GetBalance
                wallet=wallet
            />
            <GetAddress
                  wallet=wallet_1
            />
           <Send
             wallet=wallet_2/>


        }
    });

    Ok(())
}

#[component]
pub fn GetAddress(wallet: Arc<Mutex<Wallet<MemoryDatabase>>>) -> impl IntoView {
    let (value, set_value) = create_signal("".to_string());

    spawn_local({
        let wallet = wallet.clone();
        async move {
            let address = wallet.lock().await.get_address(New).unwrap().to_string();
            set_value.set(address);
        }
    });

    let update_address = {
        let wallet = wallet.clone();
        move |_| {
            spawn_local({
                let wallet = wallet.clone();
                async move {
                    let new_address = wallet.lock().await.get_address(New).unwrap().to_string();
                    set_value.set(new_address);
                }
            });
        }
    };

    view! {
         <div>
                <span>"Address: " {value}</span>
                <button on:click=update_address>"🔁"</button>
            </div>
    }
}

#[component]
pub fn GetBalance(wallet: Arc<Mutex<Wallet<MemoryDatabase>>>) -> impl IntoView {
    let (value, set_value) = create_signal("syncing wallet...".to_string());
    spawn_local(async move {
        let blockchain = EsploraBlockchain::new("https://mutinynet.com/api/", 20);

        let wallet = wallet.lock().await;

        wallet
            .sync(&blockchain, SyncOptions::default())
            .await
            .unwrap();

        set_value.update(|value| {
            *value = wallet.get_balance().unwrap().confirmed.to_string();
        });
    });
    view! {
         <div>
            <span>"Balance: " {value}</span>
        </div>
    }
}

#[component]
pub fn Send(wallet: Arc<Mutex<Wallet<MemoryDatabase>>>) -> impl IntoView {
    let (value, set_value) = create_signal("".to_string());
    let (address, set_address) = create_signal("".to_string());
    let (amount, set_amount) = create_signal("".to_string());
    let input_element_address: NodeRef<html::Input> = create_node_ref();
    let input_element_amount: NodeRef<html::Input> = create_node_ref();
    let on_submit_address = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();

        let address = input_element_address()
            .expect("<input> should be mounted")
            .value();
        set_address(address);
    };
    let on_submit_amount = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();

        let amount = input_element_amount()
            .expect("<input> should be mounted")
            .value();
        set_amount(amount);
    };
    view! {
        <div>
         <form on:submit=on_submit_address>
        <input type="text"
            value=address
            node_ref=input_element_address
        />
        <input type="submit" value="set address"/>
    </form>
     </div>
         <div>
             <form on:submit=on_submit_amount>
        <input type="text"
            value=amount
            node_ref=input_element_amount
        />
        <input type="submit" value="set amount"/>
    </form>
              </div>
     <div>
            <button on:click=move |_| {
                let address = address.get().clone();
                let amount = amount.get().clone();
                broadcast_tx(address, amount, set_value, wallet.clone());
            }>"SEND"</button>
            <p>"txid:" {value}</p>
        </div>
    }
}

fn broadcast_tx(
    address: String,
    amount: String,
    set_value: WriteSignal<String>,
    wallet: Arc<Mutex<Wallet<MemoryDatabase>>>,
) {
    spawn_local(async move {
        info!("Broadcasting tx to: {} with amount: {}", address, amount);

        let wallet = wallet.lock().await;

        let mut tx_builder = wallet.build_tx();

        let address = Address::from_str(&address)
            .unwrap()
            .require_network(Network::Signet)
            .unwrap();

        tx_builder
            .add_recipient(address.script_pubkey(), amount.parse::<u64>().unwrap())
            .enable_rbf();

        let mut psbt = tx_builder.finish().unwrap();
        wallet.sign(&mut psbt.0, SignOptions::default()).unwrap();
        let tx = psbt.0.extract_tx();
        let tx_clone = tx.clone();
        let client = esplora_client::Builder::new("https://mutinynet.com/api/")
            .build_async()
            .unwrap();

        client.broadcast(&tx).await.unwrap();
        info!("Tx broadcasted! Txid: {}", tx.txid());
        set_value(tx_clone.txid().to_string());
    });
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
