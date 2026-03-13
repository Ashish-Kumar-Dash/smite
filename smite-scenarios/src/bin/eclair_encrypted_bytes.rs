use smite::scenarios::smite_run;
use smite_scenarios::scenarios::EncryptedBytesScenario;
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<EncryptedBytesScenario<EclairTarget>>()
}
