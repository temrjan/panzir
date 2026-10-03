fn controlled_refusal(op: Op) -> OpOutcome {
    use secrecy::ExposeSecret as _;
    match op {
        Op::Open { passphrase, .. } | Op::Create { passphrase, .. } => {
            assert!(
                [OLD_SECRET, "synthetic-new-password", "new-secret"]
                    .contains(&passphrase.expose_secret())
            );
        }
        Op::Delete {
            passphrase: Some(passphrase),
            ..
        } => {
            assert!([OLD_SECRET, "synthetic-new-password"].contains(&passphrase.expose_secret()));
        }
        _ => {}
    }
    OpOutcome::Failed("synthetic controlled refusal".into())
}

// Included in app::tests; fixtures and helpers use temporary paths only.
const OLD_SECRET: &str = "synthetic-old-password";

fn ui_click(h: &mut Harness<'static, App>, label: &str) {
    h.get_by_label(label).scroll_to_me();
    h.run();
    h.get_by_label(label).click();
    h.run();
}

fn text_event(h: &mut Harness<'static, App>, id: egui::Id, text: &str, time: f64) {
    h.ctx.memory_mut(|m| m.request_focus(id));
    h.input_mut().time = Some(time.max(h.ctx.input(|i| i.time) + 1.0));
    h.event(egui::Event::Text(text.into()));
    h.step();
    h.input_mut().time = Some((time + 2.0).max(h.ctx.input(|i| i.time) + 2.0));
    h.step();
}

fn history_key(
    h: &mut Harness<'static, App>,
    id: egui::Id,
    key: egui::Key,
    shift: bool,
    time: f64,
) {
    h.ctx.memory_mut(|m| m.request_focus(id));
    h.input_mut().time = Some(time.max(h.ctx.input(|i| i.time) + 1.0));
    h.event(egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers {
            ctrl: true,
            command: true,
            shift,
            ..Default::default()
        },
    });
    h.step();
}

fn card_text<'a>(h: &'a Harness<'static, App>, delete: bool) -> &'a str {
    if delete {
        h.state()
            .delete
            .as_ref()
            .expect("delete mode")
            .passphrase
            .as_str()
    } else {
        h.state()
            .unlock
            .as_ref()
            .expect("unlock mode")
            .text
            .as_str()
    }
}

fn begin_password(h: &mut Harness<'static, App>, delete: bool) -> egui::Id {
    if delete {
        if h.query_by_label("Удалить из списка t-alpha").is_none() {
            ui_click(h, "Подробнее t-alpha");
        }
        ui_click(h, "Удалить из списка t-alpha");
    } else {
        ui_click(h, "Открыть хранилище t-alpha");
    }
    theme::id("t-alpha", if delete { "delete-password" } else { "unlock" })
}

#[test]
fn redesign_addressed_second_action_and_device_refusal() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let second = VaultEntry::new(
        Label::new("second").expect("label"),
        VaultKind::File(dir.path().join("second.vault")),
        VaultState::Disconnected,
    );
    h.state_mut().entries.push(second);
    h.run();
    ui_click(&mut h, "Открыть хранилище second");
    assert_eq!(
        h.state()
            .unlock
            .as_ref()
            .expect("second draft")
            .target
            .as_str(),
        "second"
    );
    assert!(h.state().unlock.as_ref().expect("draft").text.is_empty());
    ui_click(&mut h, "Открыть хранилище t-beta");
    assert!(h.state().unlock.is_none());
    assert!(h.state().pending.is_none());
    h.get_by_label_contains("Носители пока не поддерживаются");
}

#[test]
fn redesign_own_details_preserves_secret_history_and_cancel_restores_focus() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let id = begin_password(&mut h, false);
    text_event(&mut h, id, OLD_SECRET, 10.0);
    ui_click(&mut h, "Подробнее t-alpha");
    assert_eq!(card_text(&h, false), OLD_SECRET);
    let entries = h.state().entries.clone();
    h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
    h.run();
    history_key(&mut h, id, egui::Key::Z, false, 15.0);
    assert!(card_text(&h, false).is_empty());
    history_key(&mut h, id, egui::Key::Y, false, 16.0);
    assert_eq!(card_text(&h, false), OLD_SECRET);
    history_key(&mut h, id, egui::Key::Z, false, 17.0);
    history_key(&mut h, id, egui::Key::Z, true, 18.0);
    assert_eq!(card_text(&h, false), OLD_SECRET);
    h.key_press(egui::Key::Escape);
    h.run();
    assert!(h.state().unlock.is_none());
    assert!(h.get_by_label("Открыть хранилище t-alpha").is_focused());
}

#[test]
fn redesign_card_secret_exit_matrix_blocks_old_undo_and_dispatch() {
    for delete in [false, true] {
        for exit in [
            "cancel",
            "details-other",
            "collapse",
            "rename",
            "ssh",
            "switch",
            "create",
            "repeat-delete",
            "invalid",
            "removed",
            "external-open",
            "submit-failure",
        ] {
            if !delete && exit == "repeat-delete" {
                continue;
            }
            if delete && exit == "external-open" {
                continue;
            }
            let dir = tempfile::tempdir().expect("fixture");
            let mut h = harness_at(fixture(dir.path()));
            h.state_mut().test_operation = Some(controlled_refusal);
            let id = begin_password(&mut h, delete);
            text_event(&mut h, id, OLD_SECRET, 10.0);
            assert_eq!(
                card_text(&h, delete),
                OLD_SECRET,
                "{delete}/{exit}: input did not reach TextEdit"
            );
            let ctx = h.ctx.clone();
            let alpha = Label::new("t-alpha").expect("label");
            match exit {
                "cancel" => {
                    h.key_press(egui::Key::Escape);
                    h.run();
                }
                "details-other" => ui_click(&mut h, "Подробнее t-beta"),
                "collapse" => {
                    if h.query_by_label("Свернуть t-alpha").is_none() {
                        ui_click(&mut h, "Подробнее t-alpha");
                    }
                    ui_click(&mut h, "Свернуть t-alpha");
                }
                "rename" => h
                    .state_mut()
                    .handle(&ctx, ListAction::BeginRename(alpha.clone())),
                "ssh" => h
                    .state_mut()
                    .handle(&ctx, ListAction::BeginSshHost(alpha.clone())),
                "switch" => h
                    .state_mut()
                    .handle(&ctx, ListAction::AskDelete(alpha.clone())),
                "create" => {
                    ui_click(&mut h, "Создать хранилище");
                    h.state_mut().handle_create(&ctx, CreateAction::Cancel);
                }
                "repeat-delete" => h
                    .state_mut()
                    .handle(&ctx, ListAction::AskDelete(alpha.clone())),
                "invalid" => {
                    let mut entries = h.state().entries.clone();
                    entries[0] = VaultEntry::new(
                        alpha.clone(),
                        VaultKind::File(dir.path().join("replacement.vault")),
                        VaultState::Closed,
                    );
                    h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
                }
                "removed" => {
                    let entries = h
                        .state()
                        .entries
                        .iter()
                        .filter(|e| e.label() != &alpha)
                        .cloned()
                        .collect();
                    h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
                }
                "external-open" => {
                    let mut entries = h.state().entries.clone();
                    entries[0]
                        .set_state(VaultState::Open {
                            mount_point: dir.path().join("mnt"),
                            until: None,
                        })
                        .expect("state");
                    h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
                }
                "submit-failure" => {
                    h.state_mut().op_timeout = Duration::ZERO;
                    h.state_mut().handle(
                        &ctx,
                        if delete {
                            ListAction::ConfirmDelete
                        } else {
                            ListAction::Open(alpha.clone())
                        },
                    );
                    h.state_mut().block_until_idle();
                }
                _ => unreachable!(),
            }
            assert!(
                h.state().unlock.as_ref().is_none_or(|d| d.text.is_empty()),
                "{delete}/{exit}: abandoned Unlock still holds input"
            );
            assert!(
                h.state()
                    .delete
                    .as_ref()
                    .is_none_or(|d| d.passphrase.is_empty()),
                "{delete}/{exit}: abandoned Delete still holds input"
            );
            if matches!(exit, "invalid" | "removed" | "external-open") {
                assert!(
                    h.state().unlock.is_none() && h.state().delete.is_none(),
                    "target invalidation must end mode"
                );
            }
            // Re-enter the same visual role with its deliberately stable ID.
            if matches!(exit, "invalid" | "removed" | "external-open") {
                h.state_mut().entries[0] = VaultEntry::new(
                    alpha.clone(),
                    VaultKind::File(dir.path().join("t-alpha.vault")),
                    VaultState::Closed,
                );
            }
            h.state_mut().handle(
                &ctx,
                if delete {
                    ListAction::AskDelete(alpha.clone())
                } else {
                    ListAction::BeginUnlock(alpha.clone())
                },
            );
            h.run();
            assert!(
                card_text(&h, delete).is_empty(),
                "{delete}/{exit}: reopened draft"
            );
            let before = h.state().sequence;
            for (index, (key, shift)) in [
                (egui::Key::Z, false),
                (egui::Key::Y, false),
                (egui::Key::Z, true),
                (egui::Key::Z, false),
                (egui::Key::Y, false),
            ]
            .into_iter()
            .enumerate()
            {
                history_key(&mut h, id, key, shift, 30.0 + index as f64);
                assert!(
                    card_text(&h, delete).is_empty(),
                    "{delete}/{exit}: restored old secret via {key:?}"
                );
            }
            h.state_mut().handle(
                &ctx,
                if delete {
                    ListAction::ConfirmDelete
                } else {
                    ListAction::Open(alpha.clone())
                },
            );
            assert_eq!(
                h.state().sequence,
                before,
                "{delete}/{exit}: forbidden empty/old dispatch"
            );
            text_event(&mut h, id, "synthetic-new-password", 40.0);
            assert_eq!(card_text(&h, delete), "synthetic-new-password");
            h.state_mut().op_timeout = Duration::ZERO;
            h.state_mut().handle(
                &ctx,
                if delete {
                    ListAction::ConfirmDelete
                } else {
                    ListAction::Open(alpha)
                },
            );
            assert_eq!(h.state().sequence, before + 1);
            h.state_mut().block_until_idle();
        }
    }
}

#[test]
fn redesign_creation_history_clear_on_cancel_submit_return_failure_and_retry() {
    for exit in ["cancel", "submit", "return", "failure", "retry"] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at(fixture(dir.path()));
        h.state_mut().test_operation = Some(controlled_refusal);
        start_create(&mut h);
        for (role, time) in [("passphrase", 10.0), ("confirm", 15.0)] {
            text_event(&mut h, theme::id("create", role), OLD_SECRET, time);
        }
        assert_eq!(
            h.state().create.as_ref().expect("create").passphrase,
            OLD_SECRET
        );
        assert_eq!(
            h.state().create.as_ref().expect("create").confirm,
            OLD_SECRET
        );
        let ctx = h.ctx.clone();
        if exit == "cancel" {
            h.key_press(egui::Key::Escape);
            h.run();
            start_create(&mut h);
        } else {
            h.state_mut().create.as_mut().expect("create").label = "new-vault".into();
            h.state_mut().op_timeout = Duration::ZERO;
            h.state_mut().handle_create(&ctx, CreateAction::Submit);
            assert_eq!(h.state().screen, Screen::Create);
            if exit == "return" {
                h.state_mut().handle_create(&ctx, CreateAction::Cancel);
                h.state_mut().block_until_idle();
                h.run();
                start_create(&mut h);
            } else {
                h.state_mut().block_until_idle();
            }
        }
        for role in ["passphrase", "confirm"] {
            let id = theme::id("create", role);
            for (index, (key, shift)) in [
                (egui::Key::Z, false),
                (egui::Key::Y, false),
                (egui::Key::Z, true),
                (egui::Key::Z, false),
            ]
            .into_iter()
            .enumerate()
            {
                history_key(&mut h, id, key, shift, 30.0 + index as f64);
                let d = h.state().create.as_ref().expect("create");
                assert!(
                    d.passphrase.is_empty() && d.confirm.is_empty(),
                    "{exit}/{role}: history restored a secret"
                );
            }
        }
        let before = h.state().sequence;
        h.state_mut().handle_create(&ctx, CreateAction::Submit);
        assert_eq!(h.state().sequence, before);
        text_event(
            &mut h,
            theme::id("create", "passphrase"),
            "new-secret",
            40.0,
        );
        text_event(&mut h, theme::id("create", "confirm"), "new-secret", 45.0);
        if exit == "retry" {
            h.state_mut().create.as_mut().expect("create").label = "new-vault".into();
            h.state_mut().handle_create(&ctx, CreateAction::Submit);
            assert_eq!(h.state().sequence, before + 1);
            h.state_mut().block_until_idle();
        }
    }
}

#[test]
fn redesign_delete_enter_does_not_dispatch_and_validation_preserves_history() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let id = begin_password(&mut h, true);
    text_event(&mut h, id, OLD_SECRET, 10.0);
    h.key_press(egui::Key::Enter);
    h.run();
    assert!(h.state().pending.is_none());
    assert_eq!(card_text(&h, true), OLD_SECRET);
    let ctx = h.ctx.clone();
    h.state_mut().handle(&ctx, ListAction::StartCreate);
    h.run();
    text_event(&mut h, theme::id("create", "passphrase"), OLD_SECRET, 20.0);
    text_event(&mut h, theme::id("create", "confirm"), "mismatch", 25.0);
    h.state_mut().handle_create(&ctx, CreateAction::Submit);
    assert!(h.state().pending.is_none());
    assert_eq!(
        h.state().create.as_ref().expect("create").passphrase,
        OLD_SECRET
    );
}

#[test]
fn redesign_notices_survive_reload_in_both_orders_and_missing_card() {
    for reload_first in [true, false] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at(fixture(dir.path()));
        let entries = h.state().entries.clone();
        let label = Label::new("t-alpha").expect("label");
        let op = Operation::from_op(
            &Op::Close {
                label: label.clone(),
                container: dir.path().join("t-alpha.vault"),
            },
            h.state().sequence,
        );
        if reload_first {
            h.state_mut()
                .apply_read(Ok(OpOutcome::Loaded(entries.clone())));
        }
        h.state_mut().pending_meta = Some(op);
        h.state_mut()
            .apply(Ok(OpOutcome::Failed("synthetic-foreground-refusal".into())));
        if !reload_first {
            h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
        }
        h.state_mut()
            .apply_read(Ok(OpOutcome::Failed("synthetic-read-refusal".into())));
        h.run();
        h.get_by_label_contains("synthetic-foreground-refusal");
        h.get_by_label_contains("synthetic-read-refusal");
        h.state_mut().apply_read(Ok(OpOutcome::Loaded(vec![])));
        h.run();
        h.get_by_label_contains("synthetic-foreground-refusal");
        assert!(h.state().read_error.is_none());
        assert_eq!(h.state().notices[0].scope, NoticeScope::Card(label));
    }
}

#[test]
fn redesign_dispatch_aborts_older_read_and_busy_rejects_mutations() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let ctx = h.ctx.clone();
    let tick = h
        .state()
        .spawn_waking(&ctx, std::future::pending::<OpOutcome>());
    h.state_mut().reload_tick = Some(tick);
    h.state_mut().op_timeout = Duration::ZERO;
    assert!(h.state_mut().spawn_op(&ctx, Op::Reload));
    assert!(h.state().reload_tick.is_none());
    let before = h.state().sequence;
    h.state_mut().handle(
        &ctx,
        ListAction::AskDelete(Label::new("t-alpha").expect("label")),
    );
    h.state_mut().handle(&ctx, ListAction::StartCreate);
    assert_eq!(h.state().sequence, before);
    assert!(h.state().delete.is_none());
    assert_eq!(h.state().screen, Screen::List);
    h.state_mut().block_until_idle();
}

#[test]
fn redesign_loaded_with_create_outcomes_and_nonsecret_failure_draft() {
    for return_to_list in [false, true] {
        for success in [false, true] {
            let dir = tempfile::tempdir().expect("fixture");
            let mut h = harness_at(fixture(dir.path()));
            start_create(&mut h);
            fill_valid_create(&mut h);
            let ctx = h.ctx.clone();
            let label = Label::new("work").expect("label");
            let op = Operation::from_op(
                &Op::Create {
                    label: label.clone(),
                    container: dir.path().join("work.vault"),
                    size_bytes: 32 << 20,
                    passphrase: SecretString::from("synthetic"),
                },
                h.state().sequence,
            );
            let never = h
                .state()
                .spawn_waking(&ctx, std::future::pending::<OpOutcome>());
            h.state_mut().pending = Some(never);
            h.state_mut().pending_meta = Some(op);
            h.state_mut().create_result_target = Some(label.clone());
            h.state_mut().clear_create_passwords();
            if return_to_list {
                h.state_mut().handle_create(&ctx, CreateAction::Cancel);
            }
            h.state_mut().pending.take().expect("pending").abort();
            let mut entries = h.state().entries.clone();
            entries.push(VaultEntry::new(
                label.clone(),
                VaultKind::File(dir.path().join("work.vault")),
                VaultState::Open {
                    mount_point: dir.path().join("mnt"),
                    until: None,
                },
            ));
            h.state_mut().apply(Ok(if success {
                OpOutcome::LoadedWith(entries, "synthetic-partial-warning".into())
            } else {
                OpOutcome::Failed("synthetic-create-refusal".into())
            }));
            h.run();
            if success {
                assert_eq!(h.state().screen, Screen::List);
                assert!(
                    h.state().entries.iter().any(
                        |e| e.label() == &label && matches!(e.state(), VaultState::Open { .. })
                    )
                );
                h.get_by_label_contains("synthetic-partial-warning");
            } else {
                assert_eq!(
                    h.state().screen,
                    if return_to_list {
                        Screen::List
                    } else {
                        Screen::Create
                    }
                );
                h.get_by_label_contains("synthetic-create-refusal");
                if !return_to_list {
                    let d = h.state().create.as_ref().expect("draft");
                    assert_eq!(d.label, "work");
                    assert_eq!(d.size, "64");
                    assert!(d.passphrase.is_empty() && d.confirm.is_empty());
                }
            }
        }
    }
}

#[test]
fn redesign_stale_ssh_same_label_changed_hosts_state_or_locator_is_rejected() {
    for input in ["hosts", "state", "locator"] {
        let dir = tempfile::tempdir().expect("fixture");
        let (registry, _) = fixture_ssh(dir.path());
        let mut h = harness_at(registry);
        h.state_mut().expanded = Some(Label::new("t-alpha").expect("label"));
        h.state_mut().ssh_probe_key = h.state().current_ssh_key();
        match input {
            "hosts" => h.state_mut().entries[0].add_ssh_host(
                SshHost::new("other", "192.0.2.2", "user", None, "key").expect("host"),
            ),
            "state" => h.state_mut().entries[0]
                .set_state(VaultState::Open {
                    mount_point: dir.path().join("mnt"),
                    until: None,
                })
                .expect("state"),
            _ => {
                h.state_mut().entries[0] = VaultEntry::new(
                    Label::new("t-alpha").expect("label"),
                    VaultKind::File(dir.path().join("other.vault")),
                    VaultState::Closed,
                );
            }
        }
        h.state_mut().accept_ssh_status(SshCardStatus {
            label: Label::new("t-alpha").expect("label"),
            include: IncludeStatus::Ok,
            collision: None,
            error: None,
            resolutions: vec![],
        });
        assert!(h.state().ssh_status.is_none(), "accepted stale {input}");
    }
}

#[test]
fn redesign_holder_probe_is_single_flight_and_time_bounded() {
    let dir = tempfile::tempdir().expect("fixture");
    let (registry, mount) = fixture_open(dir.path());
    let mut h = harness_at(registry);
    h.state_mut().expanded = Some(Label::new("t-open").expect("label"));
    h.state_mut().entries[0].note_close_deferred(1);
    let ctx = h.ctx.clone();
    let held = h
        .state()
        .spawn_waking(&ctx, std::future::pending::<HolderStatus>());
    h.state_mut().holder_probe = Some(held);
    for _ in 0..100 {
        h.input_mut().time = Some(10.0);
        h.step();
    }
    assert!(h.state().holder_status.is_none());
    h.state_mut()
        .holder_probe
        .take()
        .expect("one pending")
        .abort();
    h.state_mut().holder_status = Some(HolderStatus {
        label: Label::new("t-open").expect("label"),
        mount_point: mount,
        names: vec!["synthetic-program".into()],
    });
    h.state_mut().holder_next = 20.0;
    h.state_mut().holder_requested = h.state().holder_target();
    for _ in 0..100 {
        h.input_mut().time = Some(15.0);
        h.step();
        assert!(h.state().holder_probe.is_none());
    }
    h.input_mut().time = Some(20.0);
    h.step();
    assert!(h.state().holder_probe.is_some());
}

#[test]
fn redesign_minimum_create_footer_stays_visible_at_both_zooms() {
    for zoom in [1.0, 1.25] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at_size(fixture(dir.path()), [560.0, 440.0]);
        h.ctx.set_zoom_factor(zoom);
        h.run();
        start_create(&mut h);
        let bounds = h
            .get_by_label("Создать хранилище")
            .accesskit_node()
            .bounding_box()
            .expect("button rect");
        let cancel = h
            .get_by_label("Отмена")
            .accesskit_node()
            .bounding_box()
            .expect("cancel rect");
        assert!(
            bounds.y1 <= 440.0 && bounds.x1 <= 560.0,
            "{zoom}: submit outside native rect: {bounds:?}"
        );
        assert!(
            cancel.y1 <= 440.0 && cancel.x1 <= 560.0,
            "{zoom}: cancel outside native rect"
        );
        assert!(bounds.height() >= 42.0 * f64::from(zoom));
        let d = h.state_mut().create.as_mut().expect("draft");
        d.label = "invalid-long-name".repeat(32);
        d.size = "bad".into();
        d.confirm = "different".into();
        h.run();
        assert!(
            h.get_by_label("Создать хранилище")
                .accesskit_node()
                .bounding_box()
                .expect("bounds")
                .y1
                <= 440.0
        );
    }
}

#[test]
fn redesign_label_size_boundaries_match_core() {
    for (label, valid) in [
        ("a", true),
        ("abcdefghijklmnop", true),
        ("abcdefghijklmnopq", false),
        ("-a", false),
        ("a-", false),
        ("название", false),
    ] {
        assert_eq!(Label::new(label).is_ok(), valid);
    }
    for (size, valid) in [
        ("31", false),
        ("32", true),
        (" 32 ", true),
        ("32junk", false),
        ("17592186044415", true),
        ("17592186044416", false),
    ] {
        assert_eq!(view_create::parse_size(size).is_some(), valid);
    }
}

#[test]
fn redesign_ssh_port_extremes_and_rename_failure_keep_input() {
    for port in ["", "0", "65535"] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at(fixture(dir.path()));
        start_ssh_draft(&mut h);
        fill_ssh_draft(&mut h, "devbox", port);
        ui_click(&mut h, "Сохранить хост");
        settle(&mut h);
        assert_eq!(
            h.state().entries[0].ssh_hosts()[0].port,
            if port.is_empty() {
                None
            } else {
                Some(port.parse().expect("port"))
            }
        );
    }
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let ctx = h.ctx.clone();
    h.state_mut().handle(
        &ctx,
        ListAction::BeginRename(Label::new("t-alpha").expect("label")),
    );
    h.run();
    h.state_mut().rename.as_mut().expect("rename").text = "t-beta".into();
    ui_click(&mut h, "Сохранить");
    settle(&mut h);
    assert_eq!(
        h.state().rename.as_ref().expect("failure keeps draft").text,
        "t-beta"
    );
}

struct NativeFixture {
    app: App,
    output: PathBuf,
    scene: usize,
    frames: u32,
    requested: bool,
    base: Vec<VaultEntry>,
    keyboard_step: usize,
    keyboard_deadline: f64,
}

fn native_window_focus() {
    // Actual X11 events, delivered through winit into the native viewport.
    let window = std::process::Command::new("xdotool")
        .args([
            "search",
            "--onlyvisible",
            "--name",
            "^panzir visual fixture$",
        ])
        .output()
        .expect("xdotool installed for native keyboard acceptance");
    assert!(window.status.success());
    let id = String::from_utf8(window.stdout).expect("window ID");
    assert!(
        std::process::Command::new("xdotool")
            .args(["windowfocus", "--sync", id.trim()])
            .status()
            .expect("focus native window")
            .success()
    );
}

fn native_tab(shift: bool) {
    native_window_focus();
    assert!(
        std::process::Command::new("xdotool")
            .args([
                "key",
                "--clearmodifiers",
                if shift { "shift+Tab" } else { "Tab" }
            ])
            .status()
            .expect("native Tab event")
            .success()
    );
}

const NATIVE_SCENES: &[(&str, [f32; 2], f32)] = &[
    ("list", [760.0, 560.0], 1.0),
    ("unlock", [760.0, 560.0], 1.0),
    ("create", [760.0, 560.0], 1.0),
    ("create-small", [560.0, 440.0], 1.0),
    ("create-small-125", [560.0, 440.0], 1.25),
    ("many-small-125", [560.0, 440.0], 1.25),
    ("error", [760.0, 560.0], 1.0),
    ("rename", [760.0, 560.0], 1.0),
    ("ssh", [760.0, 560.0], 1.0),
    ("delete", [560.0, 440.0], 1.0),
    ("orphan", [560.0, 440.0], 1.25),
    ("busy", [560.0, 440.0], 1.25),
    ("deferred", [760.0, 560.0], 1.0),
    ("empty", [760.0, 560.0], 1.0),
    ("include", [760.0, 560.0], 1.0),
    ("include-shadowed", [560.0, 440.0], 1.25),
    ("keyboard-small", [560.0, 440.0], 1.0),
    ("keyboard-small-125", [560.0, 440.0], 1.25),
];
impl eframe::App for NativeFixture {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::BACKGROUND.to_normalized_gamma_f32()
    }
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        use std::io::Write as _;
        let ctx = ui.ctx().clone();
        if self.scene >= NATIVE_SCENES.len() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let captures = ctx.input(|i| {
            i.events
                .iter()
                .filter_map(|e| {
                    if let egui::Event::Screenshot { image, .. } = e {
                        Some(image.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        });
        if let Some(image) = captures.first() {
            let name = NATIVE_SCENES[self.scene].0;
            let size = NATIVE_SCENES[self.scene].1;
            assert_eq!(
                [image.width(), image.height()],
                [size[0] as usize, size[1] as usize],
                "native client size {name}"
            );
            let mut file = std::fs::File::create(self.output.join(format!("{name}.ppm")))
                .expect("capture file");
            write!(file, "P6\n{} {}\n255\n", image.width(), image.height()).expect("header");
            for p in &image.pixels {
                file.write_all(&p.to_array()[..3]).expect("pixel");
            }
            println!(
                "native capture {name}: {}x{}",
                image.width(),
                image.height()
            );
            self.scene += 1;
            self.frames = 0;
            self.requested = false;
            if self.scene == NATIVE_SCENES.len() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        }
        let (name, size, zoom) = NATIVE_SCENES[self.scene];
        if self.frames == 0 {
            println!("native scene {name}");
        }
        if self.frames == 0 {
            self.keyboard_step = 0;
            self.keyboard_deadline = 0.0;
            ctx.data_mut(|d| {
                d.remove_by_type::<egui::scroll_area::State>();
                d.remove::<egui::Id>(egui::Id::new("panzir-focus-request"));
            });
            if let Some(id) = ctx.memory(|m| m.focused()) {
                ctx.memory_mut(|m| m.surrender_focus(id));
            }
            if let Some(h) = self.app.pending.take() {
                h.abort();
            }
            self.app.pending_meta = None;
            self.app.clear_card(false);
            self.app.clear_create_passwords();
            self.app.create = None;
            self.app.screen = Screen::List;
            self.app.expanded = None;
            self.app.entries = self.base.clone();
            self.app.notices.clear();
            self.app.message = None;
            self.app.env.clear();
            self.app.read_error = None;
            self.app.load = ListLoad::Loaded;
            ctx.set_zoom_factor(zoom);
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
                560.0 / zoom,
                440.0 / zoom,
            )));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
                size[0] / zoom,
                size[1] / zoom,
            )));
            let label = Label::new("t-alpha").expect("label");
            match name {
                "unlock" => self.app.handle(&ctx, ListAction::BeginUnlock(label)),
                "create" | "create-small" | "create-small-125" | "busy" | "keyboard-small"
                | "keyboard-small-125" => {
                    self.app.handle(&ctx, ListAction::StartCreate);
                    if name == "busy" {
                        self.app.pending = Some(
                            self.app
                                .spawn_waking(&ctx, std::future::pending::<OpOutcome>()),
                        );
                        self.app.pending_meta = Some(Operation::from_op(
                            &Op::Create {
                                label,
                                container: self.app.home.join("unused.vault"),
                                size_bytes: 32 << 20,
                                passphrase: SecretString::from("synthetic"),
                            },
                            self.app.sequence,
                        ));
                    }
                }
                "many-small-125" => {
                    self.app.entries = (0..30)
                        .map(|i| {
                            VaultEntry::new(
                                Label::new(&format!("vault-{i:02}")).expect("label"),
                                VaultKind::File(self.app.home.join("x".repeat(512))),
                                VaultState::Closed,
                            )
                        })
                        .collect();
                    self.app.expanded = Some(Label::new("vault-00").expect("label"));
                }
                "error" => {
                    self.app.set_notice(NoticeScope::Card(label), "Не удалось открыть „t-alpha“".into(), "Служба дисков вернула ошибку. Повторите попытку после проверки состояния хранилища.".into());
                }
                "rename" => self.app.handle(&ctx, ListAction::BeginRename(label)),
                "ssh" => self.app.handle(&ctx, ListAction::BeginSshHost(label)),
                "delete" => self.app.handle(&ctx, ListAction::AskDelete(label)),
                "orphan" => {
                    self.app.begin_card(&label, "delete", "delete-submit", true);
                    self.app.delete = Some(DeleteDraft {
                        target: label,
                        orphan: true,
                        passphrase: String::new(),
                    });
                }
                "include" | "include-shadowed" => {
                    self.app.entries[0].add_ssh_host(
                        SshHost::new("devbox", "192.0.2.10", "user", None, "id_ed25519")
                            .expect("host"),
                    );
                    self.app.expanded = Some(label.clone());
                    self.app.ssh_status_key = self.app.current_ssh_key();
                    self.app.ssh_status = Some(SshCardStatus {
                        label: label.clone(),
                        include: if name == "include" {
                            IncludeStatus::Missing
                        } else {
                            IncludeStatus::Shadowed
                        },
                        collision: None,
                        error: None,
                        resolutions: vec![],
                    });
                    self.app.handle(
                        &ctx,
                        ListAction::AskSshInclude {
                            target: label,
                            repair: name == "include-shadowed",
                        },
                    );
                }
                "deferred" => {
                    self.app.entries[0]
                        .set_state(VaultState::Open {
                            mount_point: self.app.home.join("mnt"),
                            until: None,
                        })
                        .expect("state");
                    self.app.entries[0].note_close_deferred(1);
                    self.app.expanded = Some(label.clone());
                    self.app.holder_requested = self.app.holder_target();
                    self.app.holder_next = f64::MAX;
                    self.app.holder_status = Some(HolderStatus {
                        label,
                        mount_point: self.app.home.join("mnt"),
                        names: vec!["editor".into(), "terminal".into()],
                    });
                    self.app.env = vec![EnvLine {
                        name: "cryptsetup".into(),
                        ok: false,
                        hint: "Установите пакет cryptsetup".into(),
                    }];
                }
                "empty" => self.app.entries.clear(),
                _ => {}
            }
        }
        if self.frames < 4 {
            let scale = ctx.pixels_per_point();
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
                560.0 / scale,
                440.0 / scale,
            )));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
                size[0] / scale,
                size[1] / scale,
            )));
        }
        self.app.ui(ui, frame);
        self.frames += 1;
        let keyboard = name.starts_with("keyboard-");
        if keyboard && self.frames >= 8 && self.keyboard_step == 0 && self.keyboard_deadline == 0.0
        {
            native_window_focus();
            self.keyboard_deadline = ctx.input(|i| i.time) + 0.4;
        }
        let roles = [
            "label",
            "size",
            "passphrase",
            "confirm",
            "passphrase",
            "size",
            "label",
        ];
        if keyboard
            && self.frames >= 8
            && self.keyboard_step < roles.len()
            && ctx.input(|i| i.time) >= self.keyboard_deadline
        {
            let role = roles[self.keyboard_step];
            let response = ctx
                .read_response(theme::id("create", role))
                .expect("native focused field");
            assert!(
                response.has_focus(),
                "native {name}/{role}: wrong keyboard focus"
            );
            assert!(
                response.interact_rect.contains_rect(response.rect),
                "native {name}/{role}: keyboard focused a clipped field"
            );
            println!(
                "native keyboard {name}/step{}/{role}: rect={:?}, visible={:?}",
                self.keyboard_step, response.rect, response.interact_rect
            );
            self.keyboard_step += 1;
            if self.keyboard_step < roles.len() {
                native_tab(self.keyboard_step > 3);
                self.keyboard_deadline = ctx.input(|i| i.time) + 0.4;
            }
        }
        if self.frames >= 8 && !self.requested && (!keyboard || self.keyboard_step == roles.len()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.requested = true;
        }
        // Fixture only: advancing screenshots requires frames even without input.
        ctx.request_repaint();
    }
}

#[test]
#[ignore = "native visual acceptance: run explicitly under Xvfb with PANZIR_UI_ARTIFACTS"]
fn redesign_native_capture() {
    use winit::platform::x11::EventLoopBuilderExtX11 as _;
    let output = std::env::var_os("PANZIR_UI_ARTIFACTS")
        .map(PathBuf::from)
        .expect("explicit capture directory");
    std::fs::create_dir_all(&output).expect("capture directory");
    let dir = tempfile::tempdir().expect("fixture");
    let registry = fixture(dir.path());
    let home = dir.path().to_path_buf();
    let mut options = crate::native_options();
    options.viewport = options.viewport.with_title("panzir visual fixture");
    options.event_loop_builder = Some(Box::new(|builder| {
        builder.with_x11().with_any_thread(true);
    }));
    eframe::run_native(
        "panzir visual fixture",
        options,
        Box::new(move |cc| {
            let mut app = App::new(
                cc,
                registry.clone(),
                home.clone(),
                home.join(".ssh/config"),
                PathBuf::from("/bin/true"),
                None,
                Duration::from_secs(5),
            );
            app.block_until_idle();
            println!("native fixture initialized");
            let base = app.entries.clone();
            Ok(Box::new(NativeFixture {
                app,
                output,
                scene: 0,
                frames: 0,
                requested: false,
                base,
                keyboard_step: 0,
                keyboard_deadline: 0.0,
            }))
        }),
    )
    .expect("native render");
}

#[test]
fn redesign_app_drop_invalidates_all_four_password_histories() {
    for role in ["unlock", "delete-password", "passphrase", "confirm"] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at(fixture(dir.path()));
        let target = if matches!(role, "passphrase" | "confirm") {
            start_create(&mut h);
            "create"
        } else {
            begin_password(&mut h, role == "delete-password");
            "t-alpha"
        };
        let id = theme::id(target, role);
        text_event(&mut h, id, OLD_SECRET, 10.0);
        let ctx = h.ctx.clone();
        let time = ctx.input(|i| i.time);
        drop(h.into_state());
        let mut empty = String::new();
        ctx.memory_mut(|m| m.request_focus(id));
        for (i, (key, shift)) in [
            (egui::Key::Z, false),
            (egui::Key::Y, false),
            (egui::Key::Z, true),
        ]
        .into_iter()
        .enumerate()
        {
            let event = egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl: true,
                    command: true,
                    shift,
                    ..Default::default()
                },
            };
            ctx.run_ui(
                egui::RawInput {
                    time: Some(time + i as f64 + 2.0),
                    events: vec![event],
                    ..Default::default()
                },
                |ui| {
                    ui.add(egui::TextEdit::singleline(&mut empty).password(true).id(id));
                },
            )
            .drop_without_applying_deltas();
            assert!(empty.is_empty(), "{role}: App drop left restorable history");
        }
    }
}

#[test]
fn redesign_tab_order_and_scoped_enter_use_the_active_form() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    start_create(&mut h);
    h.ctx
        .memory_mut(|m| m.request_focus(theme::id("create", "label")));
    h.step();
    for role in ["size", "passphrase", "confirm"] {
        h.key_press(egui::Key::Tab);
        h.run();
        assert_eq!(
            h.ctx.memory(|m| m.focused()),
            Some(theme::id("create", role))
        );
    }
    h.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Tab);
    h.run();
    assert_eq!(
        h.ctx.memory(|m| m.focused()),
        Some(theme::id("create", "passphrase"))
    );
    let ctx = h.ctx.clone();
    h.state_mut().handle_create(&ctx, CreateAction::Cancel);
    h.run();
    let id = begin_password(&mut h, false);
    text_event(&mut h, id, OLD_SECRET, 10.0);
    h.state_mut().test_operation = Some(controlled_refusal);
    h.key_press(egui::Key::Enter);
    h.run();
    h.state_mut().block_until_idle();
    assert!(h.state().unlock.is_none());
    assert_eq!(h.state().sequence, 2);
}

#[test]
fn redesign_minimum_scroll_tab_reaches_comfortable_fields_and_long_paths() {
    for zoom in [1.0, 1.25] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at_size(fixture(dir.path()), [560.0, 440.0]);
        h.ctx.set_zoom_factor(zoom);
        h.run();
        start_create(&mut h);
        for role in ["label", "size", "passphrase", "confirm"] {
            let id = theme::id("create", role);
            h.ctx.memory_mut(|m| m.request_focus(id));
            h.step();
            let response = h.ctx.read_response(id).expect("field response");
            assert!(response.rect.height() >= 46.0, "{role}: field too small");
            // Accessibility ScrollIntoView uses the same ScrollArea as native Tab.
            response.scroll_to_me(Some(egui::Align::Center));
            h.run();
            let response = h.ctx.read_response(id).expect("visible response");
            assert!(
                response.rect.max.x <= 560.0 / zoom,
                "horizontal field overflow"
            );
        }
        let ctx = h.ctx.clone();
        h.state_mut().handle_create(&ctx, CreateAction::Cancel);
        h.state_mut().entries = (0..30)
            .map(|i| {
                VaultEntry::new(
                    Label::new(&format!("vault-{i:02}")).expect("label"),
                    VaultKind::File(dir.path().join("x".repeat(512))),
                    VaultState::Closed,
                )
            })
            .collect();
        h.run();
        ui_click(&mut h, "Подробнее vault-00");
        let field = h.get_by_label("Удалить из списка vault-00").rect();
        assert!(
            field.max.x <= 560.0 / zoom,
            "512-character path expands the card"
        );
    }
}

#[test]
fn redesign_loading_read_failure_and_partial_entries_are_distinct() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let ctx = h.ctx.clone();
    h.state_mut().entries.clear();
    h.state_mut().load = ListLoad::Loading;
    h.state_mut().pending = Some(
        h.state()
            .spawn_waking(&ctx, std::future::pending::<OpOutcome>()),
    );
    h.run();
    h.get_by_label("Загружаем список…");
    assert!(h.query_by_label("Хранилищ пока нет").is_none());
    assert!(
        h.get_by_label("Создать хранилище")
            .accesskit_node()
            .is_disabled()
    );
    h.state_mut().pending.take().expect("pending").abort();
    h.state_mut().apply_read(Ok(OpOutcome::Failed(
        "synthetic startup read refusal".into(),
    )));
    h.run();
    h.get_by_label("Не удалось прочитать список хранилищ");
    h.get_by_label("Обновить список");
    assert!(h.query_by_label("Хранилищ пока нет").is_none());
    let entries = vec![VaultEntry::new(
        Label::new("actual").expect("label"),
        VaultKind::File(dir.path().join("actual.vault")),
        VaultState::Closed,
    )];
    h.state_mut().apply_read(Ok(OpOutcome::LoadedWith(
        entries,
        "synthetic partial read warning".into(),
    )));
    h.run();
    h.get_by_label("actual");
    h.get_by_label_contains("synthetic partial read warning");
}

// Regression scenarios adapted from the independent review r1 probes.
// Original source and attribution are preserved in DocHub artifacts.

fn check_minimum_tab_field_visibility(zoom: f32) {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at_size(fixture(dir.path()), [560.0, 440.0]);
    h.ctx.set_zoom_factor(zoom);
    h.run();
    start_create(&mut h);
    for role in ["size", "passphrase", "confirm"] {
        h.key_press(egui::Key::Tab);
        h.run();
        let id = theme::id("create", role);
        assert_eq!(h.ctx.memory(|m| m.focused()), Some(id));
        h.step();
        h.step();
        h.run();
        let response = h.ctx.read_response(id).expect("field");
        println!(
            "forward {zoom}/{role}: rect={:?} interact={:?}",
            response.rect, response.interact_rect
        );
        let visible_from_tab = response.interact_rect.contains_rect(response.rect);
        if !visible_from_tab {
            // Positive control: an actual wheel input makes the same field
            // visible in the same viewport, without a code fix.
            h.hover_at(egui::pos2(220.0, 150.0));
            h.event(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -100.0),
                phase: egui::TouchPhase::Move,
                modifiers: egui::Modifiers::NONE,
            });
            h.run();
            let visible = h.ctx.read_response(id).expect("control field");
            println!(
                "wheel control {zoom}/{role}: interact={:?}",
                visible.interact_rect
            );
            assert!(
                visible.interact_rect.is_positive(),
                "control must expose the field"
            );
        }
        assert!(
            visible_from_tab,
            "{zoom}/{role}: Tab focused a fully clipped field"
        );
    }
    for role in ["passphrase", "size", "label"] {
        h.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Tab);
        h.run();
        let id = theme::id("create", role);
        assert_eq!(h.ctx.memory(|m| m.focused()), Some(id));
        let response = h.ctx.read_response(id).expect("field");
        println!(
            "backward {zoom}/{role}: rect={:?} interact={:?}",
            response.rect, response.interact_rect
        );
        assert!(
            response.interact_rect.contains_rect(response.rect),
            "{zoom}/{role}: Shift+Tab did not expose the full field"
        );
    }
}

#[test]
fn redesign_review_tab_keeps_minimum_form_fields_visible_at_100_percent() {
    check_minimum_tab_field_visibility(1.0);
}

#[test]
fn redesign_review_tab_keeps_minimum_form_fields_visible_at_125_percent() {
    check_minimum_tab_field_visibility(1.25);
}

#[test]
fn redesign_review_removed_middle_record_focuses_following_card() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let entries: Vec<_> = ["first", "middle", "last"]
        .into_iter()
        .map(|name| {
            VaultEntry::new(
                Label::new(name).expect("label"),
                VaultKind::File(dir.path().join(format!("{name}.vault"))),
                VaultState::Closed,
            )
        })
        .collect();
    h.state_mut().replace_entries(entries.clone());
    h.run();
    ui_click(&mut h, "Открыть хранилище middle");
    assert_eq!(
        h.ctx.memory(|m| m.focused()),
        Some(theme::id("middle", "unlock"))
    );
    h.state_mut().apply_read(Ok(OpOutcome::Loaded(vec![
        entries[0].clone(),
        entries[2].clone(),
    ])));
    h.run();
    println!(
        "focus first={}, last={}",
        h.get_by_label("Открыть хранилище first").is_focused(),
        h.get_by_label("Открыть хранилище last").is_focused()
    );
    assert!(
        h.get_by_label("Открыть хранилище last").is_focused(),
        "removed middle record must return focus to the following surviving card"
    );
}

#[test]
fn redesign_review_replaced_delete_target_returns_focus_to_visible_action() {
    let dir = tempfile::tempdir().expect("fixture");
    let mut h = harness_at(fixture(dir.path()));
    let id = begin_password(&mut h, true);
    assert_eq!(h.ctx.memory(|m| m.focused()), Some(id));
    let mut entries = h.state().entries.clone();
    entries[0] = VaultEntry::new(
        Label::new("t-alpha").expect("label"),
        VaultKind::File(dir.path().join("replacement.vault")),
        VaultState::Closed,
    );
    h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
    h.run();
    assert!(h.state().delete.is_none() && h.state().expanded.is_none());
    println!(
        "focus after replacement={:?}",
        h.ctx.memory(|m| m.focused())
    );
    assert!(
        h.get_by_label("Открыть хранилище t-beta").is_focused(),
        "replacement must focus the following visible card"
    );
}

fn wait_review_tasks(h: &Harness<'static, App>) {
    let app = h.state();
    app.rt.block_on(async {
        tokio::time::timeout(TEST_DEADLINE, async {
            while app.pending.as_ref().is_some_and(|task| !task.is_finished())
                || app
                    .ssh_probe
                    .as_ref()
                    .is_some_and(|task| !task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("controlled tasks complete");
    });
}

#[test]
fn redesign_review_old_ssh_probe_cannot_overwrite_completed_include() {
    for shadowed in [false, true] {
        for order in ["old-first", "same-cycle", "write-first"] {
            let dir = tempfile::tempdir().expect("fixture");
            let (registry, config) = fixture_ssh(dir.path());
            let label = Label::new("t-alpha").expect("label");
            let line = ssh::include_line(&ssh::snippet_path(dir.path(), &label));
            std::fs::create_dir(config.parent().expect("ssh parent")).expect("mkdir");
            std::fs::write(
                &config,
                if shadowed {
                    format!("Host foreign\n  User foreign\n{line}\n")
                } else {
                    "# synthetic config\n".into()
                },
            )
            .expect("config");
            let mut h = harness_at(registry.clone());
            expand_first_card(&mut h);
            settle(&mut h);
            ui_click(
                &mut h,
                if shadowed {
                    "Поднять строку первой t-alpha"
                } else {
                    "Включить SSH-связку t-alpha"
                },
            );
            assert!(h.state().ssh_confirm.is_some());

            // The external change preserves confirmation and starts a probe with
            // exactly the record inputs that will remain after the Include write.
            let entries = h
                .state()
                .rt
                .block_on(Registry::with_write_lock_at(&registry, |r| {
                    r.entries_mut()[0].add_ssh_host(
                        SshHost::new("external", "192.0.2.11", "user", None, "key").expect("host"),
                    );
                    Ok(r.entries().to_vec())
                }))
                .expect("external registry update");
            h.state_mut().apply_read(Ok(OpOutcome::Loaded(entries)));
            assert!(h.state().ssh_status.is_none() && h.state().ssh_confirm.is_some());
            let include = ssh::include_status(
                Some(&std::fs::read_to_string(&config).expect("old config")),
                &line,
            );
            assert_eq!(
                include,
                if shadowed {
                    IncludeStatus::Shadowed
                } else {
                    IncludeStatus::Missing
                }
            );
            let old = SshCardStatus {
                label,
                include,
                collision: None,
                error: None,
                resolutions: vec![],
            };
            let ctx = h.ctx.clone();
            let key = h.state().current_ssh_key();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            h.state_mut().ssh_probe_key = key.clone();
            h.state_mut().ssh_probe = Some(h.state().spawn_waking(&ctx, async move {
                receiver.await.expect("release controlled probe")
            }));
            h.run();
            h.get_by_label("Подтвердить").click();
            h.step(); // Start the real Include; do not drain its result yet.
            let pending = h.state_mut().pending.take().expect("Include dispatched");
            if order == "old-first" {
                assert!(sender.send(old).is_ok(), "old probe active");
                wait_review_tasks(&h);
                h.state_mut().take_finished();
                assert_eq!(
                    h.state().ssh_status.as_ref().expect("old status").include,
                    include
                );
                h.state_mut().pending = Some(pending);
                wait_review_tasks(&h);
                h.step();
            } else if order == "same-cycle" {
                assert!(sender.send(old).is_ok(), "old probe active");
                h.state_mut().pending = Some(pending);
                wait_review_tasks(&h); // Both handles ready before take_finished.
                h.step();
            } else {
                // The old response is released only after the product applies success.
                let outcome = h.state().rt.block_on(pending);
                h.state_mut().apply(outcome);
                // Abort may already have closed the receiver; either delivery
                // outcome is fine, the stale result must not become current.
                let _ = sender.send(old);
                wait_review_tasks(&h);
                h.step();
            }
            assert!(
                key == h.state().current_ssh_key(),
                "record inputs unchanged after Include"
            );
            assert!(h.state().pending_meta.is_none());
            assert_eq!(
                ssh::include_status(
                    Some(&std::fs::read_to_string(&config).expect("new config")),
                    &line
                ),
                IncludeStatus::Ok
            );
            settle(&mut h); // Wait for the new actual config read, not just a metadata reset.
            assert_eq!(
                h.state()
                    .ssh_status
                    .as_ref()
                    .expect("fresh actual status")
                    .include,
                IncludeStatus::Ok,
                "{shadowed}/{order}: stale config outcome became current"
            );
            assert!(
                h.query_by_label_contains("связка включена").is_some(),
                "{shadowed}/{order}: UI disagrees with config"
            );
            println!("Include shadowed={shadowed}, order={order}: actual config=Ok, UI=Ok");
        }
    }
}

#[test]
fn redesign_review_focus_invalidation_preserves_order_and_escape_origin() {
    for mode in ["unlock", "delete"] {
        for change in [
            "remove-first",
            "remove-middle",
            "remove-last",
            "remove-following",
            "empty",
            "replace-path",
            "replace-kind",
            "escape",
            "unchanged",
        ] {
            let dir = tempfile::tempdir().expect("fixture");
            let mut h = harness_at(fixture(dir.path()));
            let entries: Vec<_> = ["first", "middle", "last"]
                .into_iter()
                .map(|name| {
                    let path = dir.path().join(format!("{name}.vault"));
                    std::fs::write(&path, b"").expect("fixture container");
                    VaultEntry::new(
                        Label::new(name).expect("label"),
                        VaultKind::File(path),
                        VaultState::Closed,
                    )
                })
                .collect();
            h.state_mut().replace_entries(entries.clone());
            h.run();
            let target = match change {
                "remove-first" => "first",
                "remove-last" => "last",
                _ => "middle",
            };
            if mode == "delete" {
                ui_click(&mut h, &format!("Подробнее {target}"));
                ui_click(&mut h, &format!("Удалить из списка {target}"));
            } else {
                ui_click(&mut h, &format!("Открыть хранилище {target}"));
            }
            let field = theme::id(
                target,
                if mode == "delete" {
                    "delete-password"
                } else {
                    "unlock"
                },
            );
            assert_eq!(h.ctx.memory(|m| m.focused()), Some(field));
            let mut next = entries;
            match change {
                "remove-first" | "remove-middle" | "remove-last" => {
                    next.retain(|e| e.label().as_str() != target)
                }
                "remove-following" => next.truncate(1),
                "empty" => next.clear(),
                "replace-path" | "replace-kind" => {
                    next[1] = VaultEntry::new(
                        Label::new("middle").expect("label"),
                        if change == "replace-path" {
                            VaultKind::File(dir.path().join("replacement.vault"))
                        } else {
                            VaultKind::Device {
                                uuid: "synthetic".into(),
                            }
                        },
                        VaultState::Closed,
                    )
                }
                _ => {}
            }
            h.state_mut().apply_read(Ok(OpOutcome::Loaded(next)));
            h.run();
            if change == "escape" {
                h.key_press(egui::Key::Escape);
                h.run();
                assert!(
                    h.get_by_label(&format!(
                        "{} {target}",
                        if mode == "delete" {
                            "Удалить из списка"
                        } else {
                            "Открыть хранилище"
                        }
                    ))
                    .is_focused()
                );
            } else if change == "unchanged" {
                assert_eq!(h.ctx.memory(|m| m.focused()), Some(field));
                assert!(h.state().interaction.is_some());
            } else {
                assert!(h.state().interaction.is_none());
                let expected = match change {
                    "remove-first" => "Открыть хранилище middle",
                    "remove-last" | "remove-following" | "empty" => "Создать хранилище",
                    _ => "Открыть хранилище last",
                };
                assert!(
                    h.get_by_label(expected).is_focused(),
                    "{mode}/{change}: expected {expected}"
                );
            }
        }
    }
}

#[test]
fn redesign_review_focused_field_allows_manual_scroll_and_tab_back() {
    for zoom in [1.0, 1.25] {
        let dir = tempfile::tempdir().expect("fixture");
        let mut h = harness_at_size(fixture(dir.path()), [560.0, 440.0]);
        h.ctx.set_zoom_factor(zoom);
        h.run();
        start_create(&mut h);
        for _ in 0..3 {
            h.key_press(egui::Key::Tab);
            h.run();
        }
        let id = theme::id("create", "confirm");
        assert_eq!(h.ctx.memory(|m| m.focused()), Some(id));
        let before = h.ctx.read_response(id).expect("confirm").rect;
        h.hover_at(egui::pos2(200.0, 150.0));
        h.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, 100.0),
            phase: egui::TouchPhase::Move,
            modifiers: egui::Modifiers::NONE,
        });
        h.run();
        let after = h.ctx.read_response(id).expect("confirm").rect;
        assert!(
            after.top() > before.top() + 10.0,
            "wheel must not be undone by a persistent focus"
        );
        h.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Tab);
        h.run();
        let previous = h
            .ctx
            .read_response(theme::id("create", "passphrase"))
            .expect("passphrase");
        assert!(previous.interact_rect.contains_rect(previous.rect));
    }
}
