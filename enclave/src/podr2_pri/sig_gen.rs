

pub fn sig_gen<T: EncryptionType>(item: T) {
    println!("Breaking news! {}", item.summarize());
}
pub fn notify(item: impl EncryptionType) {
    println!("Breaking news! {}", item.summarize());
}