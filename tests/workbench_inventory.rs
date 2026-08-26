use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const WORKBENCHES: &[(&str, &str)] = &[
    ("auth", "auth-flow-security"),
    ("core", "surface-parity"),
    ("durability", "recovery-testing"),
    ("migrations", "ledger-repair"),
    ("push", "push-delivery-safety"),
    ("realtime", "live-subscription-testing"),
];

#[test]
fn release_contains_the_complete_workbench_set() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".workbenches");
    let actual: BTreeSet<_> = fs::read_dir(&root)
        .expect(".workbenches directory")
        .map(|entry| entry.expect("workbench entry"))
        .filter(|entry| entry.file_type().expect("workbench file type").is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<_> = WORKBENCHES
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();

    assert_eq!(actual, expected);
}

#[test]
fn every_workbench_has_resolvable_instructions_and_skill() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".workbenches");
    for (name, skill) in WORKBENCHES {
        let dir = root.join(name);
        let manifest = fs::read_to_string(dir.join("workbench.yml")).expect("workbench manifest");
        assert!(manifest.contains("spec: 0"), "{name}: missing spec");
        assert!(
            manifest.contains(&format!("name: lux-{name}")),
            "{name}: wrong public name"
        );
        assert!(
            manifest.contains("instructions: ./instructions.md"),
            "{name}: missing instructions reference"
        );
        assert!(
            manifest.contains(&format!("- ./skills/{skill}")),
            "{name}: missing skill reference"
        );
        assert!(
            fs::metadata(dir.join("instructions.md"))
                .expect("instructions file")
                .len()
                > 0,
            "{name}: empty instructions"
        );
        assert!(
            fs::metadata(dir.join("skills").join(skill).join("SKILL.md"))
                .expect("skill file")
                .len()
                > 0,
            "{name}: empty skill"
        );
    }
}
