#[cfg(unix)]
mod unix_pinned_open_tests {
    use budlum_core::consensus::filiz::read_seed_file;
    use budlum_core::crypto::primitives::{KeyPair, ValidatorKeys};
    use budlum_core::network::node::load_or_generate_identity_key;
    use budlum_core::wallet::{open_key_file, KeyFile};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
        match res {
            Ok(v) => v,
            Err(e) => panic!("{msg}: {e:?}"),
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        must(
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)),
            "set permissions",
        );
    }

    #[test]
    fn symlink_validator_and_keypair_files_are_refused() {
        let dir = must(tempfile::tempdir(), "tempdir");
        let real_vk = dir.path().join("real_vk.bin");
        let link_vk = dir.path().join("link_vk.bin");
        must(
            must(ValidatorKeys::generate(), "generate validator keys").save(&real_vk),
            "save validator keys",
        );
        must(symlink(&real_vk, &link_vk), "symlink validator keys");
        assert!(
            ValidatorKeys::load(&link_vk).is_err(),
            "ValidatorKeys::load must refuse a symlink path"
        );

        let real_kp = dir.path().join("real_kp.bin");
        let link_kp = dir.path().join("link_kp.bin");
        must(
            must(KeyPair::generate(), "generate keypair").save(&real_kp),
            "save keypair",
        );
        must(symlink(&real_kp, &link_kp), "symlink keypair");
        assert!(
            KeyPair::load(&link_kp).is_err(),
            "KeyPair::load must refuse a symlink path"
        );
    }

    #[test]
    fn symlink_password_and_wallet_key_files_are_refused() {
        let dir = must(tempfile::tempdir(), "tempdir");
        let real_pw = dir.path().join("real.pw");
        let link_pw = dir.path().join("link.pw");
        must(
            std::fs::write(&real_pw, "correct-horse-battery\n"),
            "write pw",
        );
        set_mode(&real_pw, 0o600);
        must(symlink(&real_pw, &link_pw), "symlink pw");

        let real_kf = dir.path().join("real.wallet.json");
        let link_kf = dir.path().join("link.wallet.json");
        let kf = must(
            KeyFile::seal(&[0x42u8; 32], "correct-horse-battery", 100),
            "seal wallet keyfile",
        );
        must(
            std::fs::write(&real_kf, must(serde_json::to_vec(&kf), "serialize keyfile")),
            "write keyfile",
        );
        set_mode(&real_kf, 0o600);
        must(symlink(&real_kf, &link_kf), "symlink keyfile");

        assert!(
            open_key_file(&real_kf, Some(&link_pw)).is_err(),
            "open_key_file must refuse a symlinked password file"
        );
        assert!(
            open_key_file(&link_kf, Some(&real_pw)).is_err(),
            "open_key_file must refuse a symlinked key file"
        );
        assert!(open_key_file(&real_kf, Some(&real_pw)).is_ok());
    }

    #[test]
    fn symlink_and_wide_mode_filiz_seed_files_are_refused() {
        let dir = must(tempfile::tempdir(), "tempdir");
        let real_seed = dir.path().join("real.seed");
        let link_seed = dir.path().join("link.seed");
        let wide_seed = dir.path().join("wide.seed");
        let hex_seed = format!("{}\n", "ab".repeat(32));

        must(std::fs::write(&real_seed, &hex_seed), "write real seed");
        set_mode(&real_seed, 0o600);
        must(symlink(&real_seed, &link_seed), "symlink seed");

        must(std::fs::write(&wide_seed, &hex_seed), "write wide seed");
        set_mode(&wide_seed, 0o644);

        assert!(
            read_seed_file(&link_seed).is_err(),
            "read_seed_file must refuse a symlinked seed file"
        );
        assert!(
            read_seed_file(&wide_seed).is_err(),
            "read_seed_file must refuse a world-readable seed file"
        );
        assert!(read_seed_file(&real_seed).is_ok());
    }

    #[test]
    fn node_identity_key_refuses_symlink_instead_of_following() {
        let dir = must(tempfile::tempdir(), "tempdir");
        let real_path = dir.path().join("real.key");
        let link_path = dir.path().join("link.key");
        let real_str = real_path.to_str().unwrap_or("");
        let link_str = link_path.to_str().unwrap_or("");

        let real_kp = load_or_generate_identity_key(Some(real_str));
        must(symlink(&real_path, &link_path), "symlink identity");

        let loaded_via_link = load_or_generate_identity_key(Some(link_str));
        assert_ne!(
            loaded_via_link.public().to_peer_id(),
            real_kp.public().to_peer_id(),
            "load_or_generate_identity_key must refuse symlinked key file and generate fresh identity"
        );
        let meta = must(std::fs::symlink_metadata(&link_path), "lstat link_path");
        assert!(
            meta.file_type().is_file(),
            "fresh atomic identity write must replace the symlink with a regular file"
        );
    }
}
