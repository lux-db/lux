use std::time::Duration;

#[path = "support/universal_client.rs"]
mod universal_client;

use universal_client::UniversalClient;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn universal_persistence_save_and_recover_for_embedded_and_resp() {
    for use_embedded_writer in [true, false] {
        let tmpdir = tempfile::tempdir().unwrap();
        let cfg = lux::ServerConfig {
            port: 0,
            shards: 4,
            password: String::new(),
            require_auth: false,
            save_interval: Duration::from_secs(0),
            data_dir: tmpdir.path().display().to_string(),
            ..Default::default()
        };

        let handle = lux::run_with_config(cfg.clone()).await.unwrap();
        let addr = handle.local_addr().unwrap();
        let writer = if use_embedded_writer {
            UniversalClient::embedded(handle.client())
        } else {
            UniversalClient::resp(addr)
        };

        writer.set("persist_key", "persist_val").await;
        writer.lpush("persist_list", &["a", "b", "c"]).await;
        writer.sadd("persist_set", &["x", "y"]).await;
        writer.hset("persist_hash", "f1", "v1").await;
        writer.zadd("persist_zset", 1.0, "m1").await;
        writer.zadd("persist_zset", 2.0, "m2").await;
        writer.save().await;

        drop(writer);
        handle.shutdown_and_wait().await.unwrap();

        let handle2 = lux::run_with_config(cfg).await.unwrap();
        let addr2 = handle2.local_addr().unwrap();
        let embedded = UniversalClient::embedded(handle2.client());
        let resp = UniversalClient::resp(addr2);

        for reader in [&embedded, &resp] {
            let got = reader.get("persist_key").await;
            assert!(
                got.as_ref()
                    .is_some_and(|v| String::from_utf8_lossy(v).contains("persist_val")),
                "persisted string missing: {got:?}"
            );
            assert_eq!(
                reader.llen("persist_list").await,
                3,
                "persisted list missing"
            );
            assert_eq!(
                reader.scard("persist_set").await,
                2,
                "persisted set missing"
            );
            let h = reader.hget("persist_hash", "f1").await;
            assert!(
                h.as_ref()
                    .is_some_and(|v| String::from_utf8_lossy(v).contains("v1")),
                "persisted hash missing: {h:?}"
            );
            assert_eq!(
                reader.zcard("persist_zset").await,
                2,
                "persisted zset missing"
            );
            assert_eq!(reader.dbsize().await, 5, "expected 5 keys after restart");
        }

        drop(resp);
        drop(embedded);
        handle2.shutdown_and_wait().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn universal_persistence_empty_db_starts_clean_for_embedded_and_resp() {
    let tmpdir = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        password: String::new(),
        require_auth: false,
        save_interval: Duration::from_secs(0),
        data_dir: tmpdir.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let addr = handle.local_addr().unwrap();
    let embedded = UniversalClient::embedded(handle.client());
    let resp = UniversalClient::resp(addr);

    for reader in [&embedded, &resp] {
        assert_eq!(reader.dbsize().await, 0, "fresh start should have 0 keys");
    }

    drop(resp);
    drop(embedded);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn universal_persistence_flushdb_then_save_clears_snapshot() {
    for use_embedded_writer in [true, false] {
        let tmpdir = tempfile::tempdir().unwrap();
        let cfg = lux::ServerConfig {
            port: 0,
            shards: 4,
            password: String::new(),
            require_auth: false,
            save_interval: Duration::from_secs(0),
            data_dir: tmpdir.path().display().to_string(),
            ..Default::default()
        };

        let handle = lux::run_with_config(cfg.clone()).await.unwrap();
        let addr = handle.local_addr().unwrap();
        let writer = if use_embedded_writer {
            UniversalClient::embedded(handle.client())
        } else {
            UniversalClient::resp(addr)
        };

        writer.set("k1", "v1").await;
        writer.set("k2", "v2").await;
        writer.save().await;

        let flush = writer.execute_bytes(&[b"FLUSHDB"]).await;
        assert!(flush.starts_with(b"+OK"), "FLUSHDB failed: {flush:?}");
        writer.save().await;

        drop(writer);
        handle.shutdown_and_wait().await.unwrap();

        let handle2 = lux::run_with_config(cfg).await.unwrap();
        let addr2 = handle2.local_addr().unwrap();
        let embedded = UniversalClient::embedded(handle2.client());
        let resp = UniversalClient::resp(addr2);

        for reader in [&embedded, &resp] {
            assert_eq!(
                reader.dbsize().await,
                0,
                "flushed db should be empty after restart"
            );
        }

        drop(resp);
        drop(embedded);
        handle2.shutdown_and_wait().await.unwrap();
    }
}
