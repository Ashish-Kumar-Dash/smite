//! CLN (Core Lightning) fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::EncryptedBytesScenario;
use smite_scenarios::targets::ClnTarget;

fn main() -> std::process::ExitCode {
    smite_run::<EncryptedBytesScenario<ClnTarget>>()
}
