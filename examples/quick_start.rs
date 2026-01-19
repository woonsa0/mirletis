use mirletis::{keygen, encaps, decaps};

fn main() {
    // 1. Alice generates a key pair
    let (pk, secret_vault) = keygen();

    // 2. Bob encapsulates a shared secret
    let (ct, key_bob) = encaps(&pk);

    // 3. Alice decapsulates to get the same secret
    let key_alice = decaps(&ct, &secret_vault);

    assert_eq!(key_alice.key, key_bob.key);
    println!("Shared Secret Established! 🐉");
}

