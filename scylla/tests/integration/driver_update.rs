use scylla::{DriverUpdatePolicy, DriverUpdateStatus};

/// Test that DriverUpdatePolicy derives Default correctly (Enabled).
#[test]
fn test_driver_update_policy_default() {
    let policy = DriverUpdatePolicy::default();
    assert_eq!(policy, DriverUpdatePolicy::Enabled);
}

/// Test that DriverUpdateStatus variants can be constructed and compared.
#[test]
fn test_driver_update_status_variants() {
    let updated = DriverUpdateStatus::Updated {
        version: "0.2.0".to_string(),
    };
    assert_eq!(
        updated,
        DriverUpdateStatus::Updated {
            version: "0.2.0".to_string()
        }
    );

    let fallback = DriverUpdateStatus::FallbackServerUnsupported;
    assert_eq!(fallback, DriverUpdateStatus::FallbackServerUnsupported);

    let disabled = DriverUpdateStatus::Disabled;
    assert_eq!(disabled, DriverUpdateStatus::Disabled);
}
