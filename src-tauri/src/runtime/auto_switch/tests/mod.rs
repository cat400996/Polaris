use super::*;
use serde_json::json;

// ── on_heartbeat：触发阈值真值表（别过度触发 / 别欠触发）──

#[test]
fn heartbeat_alive_when_no_prior_failures_is_stable() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert_eq!(m.on_heartbeat(true), HeartbeatOutcome::Stable);
}

#[test]
fn heartbeat_two_failures_do_not_trigger() {
    // 单次/两次瞬断不该切——别过度触发。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 2 }
    );
}

#[test]
fn heartbeat_third_consecutive_failure_triggers() {
    // 恰好第 3 次连续失败触发——变异：阈值 >= 改 > 会漏这次触发。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    assert_eq!(m.on_heartbeat(false), HeartbeatOutcome::Trigger);
}

#[test]
fn heartbeat_trigger_resets_failure_count() {
    // 触发后失败计数复位（上游 :142）——下一次失败重新从 1 计。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    assert_eq!(m.on_heartbeat(false), HeartbeatOutcome::Trigger);
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
}

#[test]
fn heartbeat_alive_resets_failure_streak() {
    // 中途恢复联通 → 失败连击清零（别欠触发的对偶：也别把不连续的失败攒成触发）。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    assert_eq!(
        m.on_heartbeat(true),
        HeartbeatOutcome::Recovered { prior: 2 }
    );
    // 复位后重新从 1 计，不会因之前 2 次就触发。
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
}

// ── evaluate_switch：冷却 / 熔断 / 在飞 真值表 ──

#[test]
fn gate_in_flight_blocks() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.begin_switch(1_000_000);
    assert_eq!(m.evaluate_switch(2_000_000), SwitchGate::InFlight);
}

#[test]
fn gate_proceeds_when_clear() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    // 尚无 last_switch_time → 首次切换直接放行。
    assert_eq!(m.evaluate_switch(10_000_000), SwitchGate::Proceed);
}

#[test]
fn first_gate_proceeds_even_when_monotonic_clock_starts_at_zero() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert_eq!(m.evaluate_switch(0), SwitchGate::Proceed);
}

#[test]
fn gate_cooldown_blocks_within_window() {
    // 距上次换节点 30s < 60s 冷却 → 拦。变异：删冷却检查会误放行。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.begin_switch(1_000_000);
    m.end_switch();
    match m.evaluate_switch(1_000_000 + 30_000) {
        SwitchGate::Cooldown { remaining_ms } => assert_eq!(remaining_ms, 30_000),
        other => panic!("期望 Cooldown，实际 {other:?}"),
    }
}

#[test]
fn gate_proceeds_after_cooldown_window() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.begin_switch(1_000_000);
    m.end_switch();
    // 距上次 60s+ → 冷却结束，放行。
    assert_eq!(m.evaluate_switch(1_000_000 + 60_001), SwitchGate::Proceed);
}

#[test]
fn gate_breaker_trips_after_max_switches() {
    // 连续切换达上限 + 未过熔断冷却 → 熔断拦。变异：删熔断检查会在整体网络故障时空转。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    // 模拟 3 次成功切换记账。
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000); // 第 3 次 → breaker_tripped_at=1_000_000
                                        // 冷却窗内（+5min < 10min）且非在飞、且冷却已过（last_switch_time=0）→ 仍应被熔断拦。
    match m.evaluate_switch(1_000_000 + 5 * 60_000) {
        SwitchGate::Breaker { remaining_ms } => assert_eq!(remaining_ms, 5 * 60_000),
        other => panic!("期望 Breaker，实际 {other:?}"),
    }
}

#[test]
fn gate_breaker_resets_and_proceeds_after_cooldown() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    // 熔断冷却过后（+10min+1）→ 复位熔断 + 放行。
    let now = 1_000_000 + BREAKER_COOLDOWN_MS + 1;
    assert_eq!(m.evaluate_switch(now), SwitchGate::Proceed);
}

#[test]
fn recovered_heartbeat_clears_breaker_count() {
    // 恢复联通 → 熔断计数清零（上游 :132）：随后连续失败触发时不再被残留计数熔断。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.on_heartbeat(true); // 恢复 → consecutive_switches 清零
                          // 冷却也已过（用远后的 now），闸门应放行（熔断计数已清）。
    assert_eq!(m.evaluate_switch(20_000_000), SwitchGate::Proceed);
}

#[test]
fn record_success_only_trips_breaker_at_threshold() {
    // 变异：把 record 的 >= 改成别的会让熔断时刻记错 → 第 3 次才置 breaker_tripped_at。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(500);
    m.record_switch_success(600);
    // 前两次：consecutive_switches<3 → 未熔断，冷却过后放行。
    assert_eq!(m.evaluate_switch(10_000_000), SwitchGate::Proceed);
}

// ── enable/disable 复位 ──

#[test]
fn enable_resets_counters() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.record_switch_success(1_000_000);
    m.disable();
    m.enable(); // 重新启用 → 复位
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
}

#[test]
fn enable_is_idempotent_no_reset_on_second_call() {
    // 幂等：已启用再 enable 不复位（否则轮询驱动的重复 enable 会抹掉进行中的失败连击 → 永不触发）。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    m.enable(); // 已启用 → no-op，不复位
    assert_eq!(m.on_heartbeat(false), HeartbeatOutcome::Trigger);
}

#[test]
fn reset_failures_only_keeps_breaker_count() {
    // 核未运行分支：只清失败、不清熔断（上游 :107-110）。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.on_heartbeat(false);
    m.reset_failures_only();
    // 失败清零：下一失败从 1 计。
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
    // 熔断计数未清：仍被熔断拦。
    assert!(matches!(
        m.evaluate_switch(1_000_000 + 60_001),
        SwitchGate::Breaker { .. }
    ));
}

// ── plan_runtime_candidates：运行态候选规划 ──

#[test]
fn plan_runtime_candidates_excludes_current() {
    let cfg = json!({
        "selectedServerId": "a",
        "servers": [
            { "id": "a", "name": "A", "address": "1.1.1.1", "port": 443 },
            { "id": "b", "name": "B", "address": "2.2.2.2", "port": 8443 },
        ]
    });
    let plan = plan_runtime_candidates(
        &cfg,
        Some("a"),
        &BTreeMap::from([(String::from("b"), String::from("b-tag"))]),
        &BTreeMap::from([(String::from("b"), String::from("fp-b"))]),
        &BTreeMap::from([(String::from("b"), String::from("fp-b"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].id, "b");
    assert_eq!(plan.candidates[0].name, "B");
    assert_eq!(plan.candidates[0].tag, "b-tag");
}

#[test]
fn plan_runtime_candidates_missing_servers_is_empty() {
    assert_eq!(
        plan_runtime_candidates(
            &json!({}),
            Some("a"),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        ),
        RuntimeCandidatePlan::default()
    );
}

#[test]
fn plan_runtime_candidates_name_falls_back_to_id() {
    let cfg = json!({ "servers": [ { "id": "x", "address": "h", "port": 1 } ] });
    let plan = plan_runtime_candidates(
        &cfg,
        None,
        &BTreeMap::from([(String::from("x"), String::from("x-tag"))]),
        &BTreeMap::from([(String::from("x"), String::from("fp-x"))]),
        &BTreeMap::from([(String::from("x"), String::from("fp-x"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert_eq!(plan.candidates[0].name, "x");
}

#[test]
fn plan_runtime_candidates_staged_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "staged", "name": "Staged" }] }),
        None,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::from([String::from("staged")]),
        &BTreeSet::new(),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.staged, 1);
}

#[test]
fn plan_runtime_candidates_not_loaded_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "disk-only" }] }),
        None,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.not_loaded, 1);
}

#[test]
fn plan_runtime_candidates_dirty_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "dirty" }] }),
        None,
        &BTreeMap::from([(String::from("dirty"), String::from("dirty-tag"))]),
        &BTreeMap::from([(String::from("dirty"), String::from("running-fp"))]),
        &BTreeMap::from([(String::from("dirty"), String::from("current-fp"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.dirty, 1);
}

#[test]
fn plan_runtime_candidates_not_ready_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "not-ready" }] }),
        None,
        &BTreeMap::from([(String::from("not-ready"), String::from("not-ready-tag"))]),
        &BTreeMap::from([(String::from("not-ready"), String::from("same-fp"))]),
        &BTreeMap::from([(String::from("not-ready"), String::from("same-fp"))]),
        &BTreeSet::new(),
        &BTreeSet::from([String::from("not-ready")]),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.not_ready, 1);
}

#[test]
fn plan_runtime_candidates_clean_is_included() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "clean", "name": "Clean" }] }),
        None,
        &BTreeMap::from([(String::from("clean"), String::from("clean-tag"))]),
        &BTreeMap::from([(String::from("clean"), String::from("same-fp"))]),
        &BTreeMap::from([(String::from("clean"), String::from("same-fp"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert_eq!(
        plan.candidates,
        vec![RuntimeCandidate {
            id: String::from("clean"),
            name: String::from("Clean"),
            tag: String::from("clean-tag"),
        }]
    );
    assert_eq!(plan.staged, 0);
    assert_eq!(plan.not_loaded, 0);
    assert_eq!(plan.dirty, 0);
    assert_eq!(plan.not_ready, 0);
}

// ── select_best_candidate：下一节点选择决策 ──

fn cand(id: &str, lat: Option<u32>) -> CandidateLatency {
    CandidateLatency {
        id: id.to_string(),
        name: format!("name-{id}"),
        latency_ms: lat,
    }
}

#[test]
fn select_picks_lowest_latency() {
    let list = vec![
        cand("a", Some(120)),
        cand("b", Some(40)),
        cand("c", Some(80)),
    ];
    assert_eq!(select_best_candidate(&list).unwrap().id, "b");
}

#[test]
fn select_skips_unreachable() {
    // 变异：不过滤 None 会把不可达当最优 → 切到死节点。
    let list = vec![cand("a", None), cand("b", Some(200))];
    assert_eq!(select_best_candidate(&list).unwrap().id, "b");
}

#[test]
fn select_none_when_all_unreachable() {
    let list = vec![cand("a", None), cand("b", None)];
    assert!(select_best_candidate(&list).is_none());
}

#[test]
fn select_empty_is_none() {
    assert!(select_best_candidate(&[]).is_none());
}

#[test]
fn select_ties_take_first() {
    let list = vec![cand("a", Some(50)), cand("b", Some(50))];
    assert_eq!(select_best_candidate(&list).unwrap().id, "a");
}

// ── switch_payload：emit payload ──

#[test]
fn switch_payload_uses_selected_candidate_fields() {
    let best = cand("new-id", Some(42));
    let payload = switch_payload(&best, "连通性检测").unwrap();
    assert_eq!(payload.reason, "连通性检测");
    assert_eq!(payload.new_server_name, "name-new-id");
    assert_eq!(payload.latency, 42);
}

#[test]
fn switch_payload_none_when_candidate_unreachable() {
    assert!(switch_payload(&cand("x", None), "r").is_none());
}

#[test]
fn payload_serializes_camel_case() {
    let p = AutoNodeSwitchedPayload {
        reason: "连通性检测".to_string(),
        new_server_name: "东京-01".to_string(),
        latency: 88,
    };
    let v = serde_json::to_value(&p).unwrap();
    assert_eq!(
        v.get("newServerName").and_then(Value::as_str),
        Some("东京-01")
    );
    assert_eq!(v.get("reason").and_then(Value::as_str), Some("连通性检测"));
    assert_eq!(v.get("latency").and_then(Value::as_u64), Some(88));
}
