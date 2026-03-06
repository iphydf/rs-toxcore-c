use merkle_tox_bench::scenario::{ScenarioCategory, all_scenarios, scenarios_by_ids};

#[test]
fn all_scenarios_returns_ten() {
    let scenarios = all_scenarios();
    assert_eq!(scenarios.len(), 10);
}

#[test]
fn scenario_ids_are_unique_and_sequential() {
    let scenarios = all_scenarios();
    for (i, s) in scenarios.iter().enumerate() {
        assert_eq!(s.id, i + 1, "Scenario at index {} has wrong id {}", i, s.id);
    }
}

#[test]
fn scenarios_have_nonzero_nodes_and_timeout() {
    for s in all_scenarios() {
        assert!(s.node_count >= 2, "Scenario {} has <2 nodes", s.name);
        assert!(!s.timeout.is_zero(), "Scenario {} has zero timeout", s.name);
        assert!(!s.phases.is_empty(), "Scenario {} has no phases", s.name);
    }
}

#[test]
fn scenarios_by_ids_filters_correctly() {
    let subset = scenarios_by_ids(&[1, 6, 10]);
    assert_eq!(subset.len(), 3);
    assert_eq!(subset[0].id, 1);
    assert_eq!(subset[1].id, 6);
    assert_eq!(subset[2].id, 10);
}

#[test]
fn scenarios_by_ids_ignores_invalid() {
    let subset = scenarios_by_ids(&[1, 99, 6]);
    assert_eq!(subset.len(), 2);
}

#[test]
fn category_counts() {
    let scenarios = all_scenarios();
    let blob_count = scenarios
        .iter()
        .filter(|s| s.category == ScenarioCategory::BlobTransfer)
        .count();
    let dag_count = scenarios
        .iter()
        .filter(|s| s.category == ScenarioCategory::DagConvergence)
        .count();
    let combined_count = scenarios
        .iter()
        .filter(|s| s.category == ScenarioCategory::Combined)
        .count();

    assert_eq!(blob_count, 5);
    assert_eq!(dag_count, 3);
    assert_eq!(combined_count, 2);
}

#[test]
fn category_display() {
    assert_eq!(format!("{}", ScenarioCategory::BlobTransfer), "Blob");
    assert_eq!(format!("{}", ScenarioCategory::DagConvergence), "DAG");
    assert_eq!(format!("{}", ScenarioCategory::Combined), "Combined");
}
