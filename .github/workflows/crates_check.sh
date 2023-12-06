cargo check -p zenoh-result --manifest-path commons/zenoh-result/Cargo.toml &&
cargo check -p zenoh-core --manifest-path commons/zenoh-core/Cargo.toml &&
cargo check -p zenoh-keyexpr --manifest-path commons/zenoh-keyexpr/Cargo.toml &&
cargo check -p zenoh-collections --manifest-path commons/zenoh-collections/Cargo.toml &&
cargo check -p zenoh-crypto --manifest-path commons/zenoh-crypto/Cargo.toml &&
cargo check -p zenoh-buffers --manifest-path commons/zenoh-buffers/Cargo.toml &&
cargo check -p zenoh-protocol --manifest-path commons/zenoh-protocol/Cargo.toml &&
cargo check -p zenoh-util --manifest-path commons/zenoh-util/Cargo.toml &&
cargo check -p zenoh-sync --manifest-path commons/zenoh-sync/Cargo.toml &&
cargo check -p zenoh-macros --manifest-path commons/zenoh-macros/Cargo.toml &&
cargo check -p zenoh-shm --manifest-path commons/zenoh-shm/Cargo.toml &&
cargo check -p zenoh-codec --manifest-path commons/zenoh-codec/Cargo.toml &&
cargo check -p zenoh-config --manifest-path commons/zenoh-config/Cargo.toml &&
cargo check -p zenoh-link-commons --manifest-path io/zenoh-link-commons/Cargo.toml &&
cargo check -p zenoh-link-udp --manifest-path io/zenoh-links/zenoh-link-udp/Cargo.toml &&
cargo check -p zenoh-link-tcp --manifest-path io/zenoh-links/zenoh-link-tcp/Cargo.toml &&
cargo check -p zenoh-link-tls --manifest-path io/zenoh-links/zenoh-link-tls/Cargo.toml &&
cargo check -p zenoh-link-quic --manifest-path io/zenoh-links/zenoh-link-quic/Cargo.toml &&
cargo check -p zenoh-link-unixpipe --manifest-path io/zenoh-links/zenoh-link-unixpipe/Cargo.toml &&
cargo check -p zenoh-link-unixsock_stream --manifest-path io/zenoh-links/zenoh-link-unixsock_stream/Cargo.toml &&
cargo check -p zenoh-link-serial --manifest-path io/zenoh-links/zenoh-link-serial/Cargo.toml &&
cargo check -p zenoh-link-ws --manifest-path io/zenoh-links/zenoh-link-ws/Cargo.toml &&
cargo check -p zenoh-link --manifest-path io/zenoh-link/Cargo.toml &&
cargo check -p zenoh-transport --manifest-path io/zenoh-transport/Cargo.toml &&
cargo check -p zenoh-plugin-trait --manifest-path plugins/zenoh-plugin-trait/Cargo.toml &&
cargo check -p zenoh --manifest-path zenoh/Cargo.toml &&
cargo check -p zenoh-ext --manifest-path zenoh-ext/Cargo.toml &&
cargo check -p zenohd --manifest-path zenohd/Cargo.toml &&
cargo check -p zenoh-plugin-rest --manifest-path plugins/zenoh-plugin-rest/Cargo.toml &&
cargo check -p zenoh_backend_traits --manifest-path plugins/zenoh-backend-traits/Cargo.toml &&
cargo check -p zenoh-plugin-storage-manager --manifest-path plugins/zenoh-plugin-storage-manager/Cargo.toml &&
true