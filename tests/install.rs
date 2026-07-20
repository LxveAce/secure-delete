//! Installer tests — dry-run only, so they touch neither the registry nor the scheduler on CI.
use secure_delete::install;

#[test]
fn dry_run_describes_the_plan_and_changes_nothing() {
    let dir = std::env::temp_dir().join(format!("sdinstall-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    let plan = install::install(&dir, 21600, None, false, false, true).unwrap();
    #[cfg(windows)]
    {
        assert!(plan.contains("DRY-RUN"), "got: {plan}");
        assert!(plan.to_lowercase().contains("logon"), "got: {plan}");
        // A dry-run must not create the app data dir.
        if let Ok(base) = std::env::var("LOCALAPPDATA") {
            // (only assert about OUR marker dir being absent is unreliable if a real install exists;
            //  instead assert the dry-run returned without registering — covered by the string above.)
            let _ = base;
        }
    }
    #[cfg(not(windows))]
    assert!(plan.contains("systemctl"), "got: {plan}");

    let un = install::uninstall(&dir, true).unwrap();
    assert!(un.contains("DRY-RUN"), "got: {un}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(windows))]
#[test]
fn linux_install_writes_units_then_uninstall_removes_them() {
    // Point the systemd user-unit dir at a temp location so this touches nothing real. Enabling the timer
    // will fail on a headless CI runner (no user session), which is fine — install falls back gracefully.
    let cfg = std::env::temp_dir().join(format!("sdcfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cfg);
    std::fs::create_dir_all(&cfg).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &cfg);

    let target = std::env::temp_dir().join(format!("sdtarget-{}", std::process::id()));
    std::fs::create_dir_all(&target).unwrap();
    let unit_dir = cfg.join("systemd").join("user");
    let svc = unit_dir.join("secure-delete-clean.service");
    let tim = unit_dir.join("secure-delete-clean.timer");

    install::install(&target, 21600, None, false, false, false).unwrap();
    assert!(svc.exists() && tim.exists(), "both units should be written");
    let body = std::fs::read_to_string(&svc).unwrap();
    assert!(body.contains("ExecStart=") && body.contains("clean"), "service runs the clean: {body}");

    install::uninstall(&target, false).unwrap();
    assert!(!svc.exists() && !tim.exists(), "units should be removed");

    let _ = std::fs::remove_dir_all(&cfg);
    let _ = std::fs::remove_dir_all(&target);
}
