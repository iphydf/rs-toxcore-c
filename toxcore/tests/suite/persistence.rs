use toxcore::tox::*;

pub fn subtest_persistence() {
    println!("Running subtest_persistence...");
    let savedata;
    let pk;
    {
        let mut opts = Options::new().unwrap();
        opts.set_ipv6_enabled(false);
        opts.set_udp_enabled(true);
        opts.set_local_discovery_enabled(false);
        let tox = Tox::new(opts).unwrap();
        tox.set_name(b"PersistentUser").unwrap();
        tox.set_status_message(b"I will be back").unwrap();
        pk = tox.public_key();
        savedata = tox.savedata();
    }

    // Restore
    let mut opts = Options::new().unwrap();
    opts.set_savedata_type(ToxSavedataType::TOX_SAVEDATA_TYPE_TOX_SAVE);
    opts.set_savedata_data(&savedata).unwrap();
    opts.set_local_discovery_enabled(false);
    let tox = Tox::new(opts).unwrap();

    assert_eq!(tox.public_key(), pk);
    assert_eq!(tox.name(), b"PersistentUser");
    assert_eq!(tox.status_message(), b"I will be back");
}
