use bud_isa::{Instruction, Opcode};
use bud_proof::adapter::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_proof::DefaultAdapter as Prover;
use bud_vm::Vm;
use clap::{Parser, Subcommand};
use std::fs;
use tiny_keccak::{Hasher, Keccak};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "BudZKVM Command Line Interface",
    long_about = "A production-grade, high-performance toolchain for compiling, executing, proving, and verifying BudZKVM smart contracts."
)]
struct Cli {
    #[arg(
        long,
        default_value_t = 1,
        help = "The unique chain identifier for execution context"
    )]
    chain_id: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Compile, execute, prove, verify, and commit state transitions for a BudL program"
    )]
    Run {
        #[arg(short, long, help = "Path to the .bud source contract file")]
        program: String,
        #[arg(short, long, help = "Optional sender account ID")]
        sender: Option<u64>,
        #[arg(short, long, help = "Optional transaction nonce")]
        nonce: Option<u64>,
        #[arg(short, long, help = "Optional block height")]
        block_height: Option<u64>,
        #[arg(short, long, help = "Arguments to pass to the main function")]
        args: Vec<u64>,
        #[arg(long, help = "Output execution result in JSON format")]
        json: bool,
        #[arg(long, help = "File path to write the generated STARK proof envelope")]
        proof_out: Option<String>,
        #[arg(
            long,
            help = "File path to write the generated execution public inputs JSON"
        )]
        public_inputs_out: Option<String>,
        #[arg(long, help = "Path to load state from (defaults to state.json)")]
        state_in: Option<String>,
        #[arg(
            long,
            help = "Path to write the updated state to (defaults to state_in)"
        )]
        state_out: Option<String>,
    },
    #[command(about = "Compile and generate a STARK proof for a program without committing state")]
    Prove {
        #[arg(short, long, help = "Path to the .bud source contract file")]
        program: String,
        #[arg(short, long, help = "Optional sender account ID")]
        sender: Option<u64>,
        #[arg(short, long, help = "Optional transaction nonce")]
        nonce: Option<u64>,
        #[arg(short, long, help = "Optional block height")]
        block_height: Option<u64>,
        #[arg(short, long, help = "Arguments to pass to the main function")]
        args: Vec<u64>,
        #[arg(long, help = "File path to write the generated STARK proof envelope")]
        proof_out: String,
        #[arg(
            long,
            help = "File path to write the generated execution public inputs JSON"
        )]
        public_inputs_out: Option<String>,
    },
    #[command(
        about = "Execute, prove, verify, and commit state for a batch of programs sequentially"
    )]
    Batch {
        #[arg(short, long, help = "List of paths to .bud source files in the batch")]
        programs: Vec<String>,
        #[arg(short, long, help = "Optional sender account ID")]
        sender: Option<u64>,
        #[arg(short, long, help = "Optional starting transaction nonce")]
        nonce: Option<u64>,
        #[arg(short, long, help = "Optional block height")]
        block_height: Option<u64>,
        #[arg(short, long, help = "Arguments to pass to each main function")]
        args: Vec<u64>,
    },
    #[command(about = "Compile a BudL program to VM bytecode file (.budc)")]
    Deploy {
        #[arg(short, long, help = "Path to the .bud source contract file")]
        program: String,
        #[arg(
            short,
            long,
            help = "Optional output file path (defaults to <program>.budc)"
        )]
        output: Option<String>,
    },
    #[command(about = "Load compiled bytecode, execute, prove, and commit state transitions")]
    Call {
        #[arg(short, long, help = "Path to the compiled .budc bytecode file")]
        bytecode: String,
        #[arg(short, long, help = "Optional sender account ID")]
        sender: Option<u64>,
        #[arg(short, long, help = "Optional transaction nonce")]
        nonce: Option<u64>,
        #[arg(short, long, help = "Arguments to pass to the main function")]
        args: Vec<u64>,
    },
    #[command(
        about = "Verify a generated STARK proof envelope against public inputs and program bytecode"
    )]
    Verify {
        // Short flags are assigned explicitly: clap derives `-p` for both
        // `proof_file` and `public_inputs_file`, and its duplicate-short
        // assertion aborts the process before any argument is parsed, so
        // `verify` (including `verify --help`) always panicked.
        #[arg(short = 'f', long, help = "Path to the STARK proof envelope JSON file")]
        proof_file: String,
        #[arg(
            short = 'i',
            long,
            help = "Path to the execution public inputs JSON file"
        )]
        public_inputs_file: String,
        #[arg(
            short = 'b',
            long,
            help = "Path to the compiled program bytecode (.budc or hex bytes)"
        )]
        bytecode_file: String,
    },
    #[command(about = "Run hardcoded smoke test of BudZKVM execution engine")]
    Test,
}

fn compute_keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut res = [0u8; 32];
    hasher.finalize(&mut res);
    res
}

struct ExecutionConfig {
    bytecode: Vec<u64>,
    sender: Option<u64>,
    nonce: Option<u64>,
    block_height: Option<u64>,
    args: Vec<u64>,
    chain_id: u64,
    state_in_file: Option<String>,
    commit_state: bool,
}

struct ExecutionOutput {
    pre_root: [u8; 32],
    post_root: [u8; 32],
    receipt: bud_vm::ExecutionReceipt,
    pi: ExecutionPublicInputs,
    envelope: ProofEnvelope,
    state: bud_state::State,
    vm: Vm,
}

fn run_pipeline(config: ExecutionConfig) -> Result<ExecutionOutput, Box<dyn std::error::Error>> {
    use bud_state::StateBackend;

    debug!("Starting pipeline");

    let state_file = config
        .state_in_file
        .unwrap_or_else(|| "state.json".to_string());
    let mut state =
        bud_state::State::load(&state_file).map_err(|e| format!("Failed to load state: {e}"))?;
    let pre_root = state.root();

    // Strix HIGH (2026-08-17): Vm::new mainnet_mode=false birakir; gated
    // opcode'lar (VerifyMerkle/VerifyInference) non-mainnet decoder'da
    // calisir. CLI varsayilani mainnet-guvenli olmali: mainnet_mode=true.
    let mut vm = Vm::with_mainnet_mode(bud_compiler::MIN_VM_MEMORY_BYTES, 1_000_000, true);
    if let Some(s) = config.sender {
        vm.context.sender = s;
        // Güvenlik denetimi (MEDIUM): kayitli olmayan bir sender icin
        // otomatik fonlu hesap olusturmak, calistiricinin kontrol ettigi
        // sender degerini ag yapisina yansitir ve "sahip olunmayan"
        // hesaptan islem basilmis gibi davranir. Fail-closed: sender
        // state'te yoksa islem reddedilir.
        let acc = state.get_account(s).ok_or_else(|| {
            format!("sender account {s} does not exist in {state_file}; refusing to fund a new account implicitly")
        })?;
        vm.context.nonce = acc.nonce;
    }
    if let Some(n) = config.nonce {
        vm.context.nonce = n;
    }
    if let Some(bh) = config.block_height {
        vm.context.block_height = bh;
    }

    for (i, val) in config.args.iter().enumerate() {
        if i < 31 {
            vm.registers[i + 1] = *val;
        }
    }

    let receipt = vm.run_receipt(&config.bytecode);
    if !receipt.success {
        return Err(format!("Execution failed deterministically: {:?}", receipt.error).into());
    }

    debug!(
        gas_used = receipt.gas_used,
        trace_len = receipt.trace_len,
        "VM execution complete"
    );

    // Apply state updates in memory if committing.
    //
    // A storage-writing contract lowers `storage::field = expr` to
    // `Opcode::SWrite`, and the VM applies those writes only to its
    // transient state, never to bud-state. Committing a `final_state_root`
    // that omits those writes would let a storage-backed contract prove and
    // commit while the persisted state excludes its transition, breaking
    // state integrity and enabling replay of one-time logic (Strix HIGH,
    // güvenlik denetimi). Until storage persistence lands in bud-state,
    // refuse to commit a run whose storage writes are non-empty.
    if config.commit_state {
        if receipt.state_writes_digest != [0u8; 32] {
            return Err(
                "Storage writes are not yet persisted into bud-state; refusing to commit an incorrect final_state_root"
                    .into(),
            );
        }
        state.begin_transaction();
        if let Some(s) = config.sender {
            let mut acc = state
                .get_account(s)
                .ok_or("Sender account not found in state")?;
            acc.nonce += 1;
            state.set_account(s, acc);
        }
    }

    let post_root = if config.commit_state {
        state.root()
    } else {
        pre_root
    };

    // Construct ExecutionPublicInputs
    let bytecode_bytes: Vec<u8> = config
        .bytecode
        .iter()
        .flat_map(|&b| b.to_le_bytes().to_vec())
        .collect();
    let prog_hash = compute_keccak256(&bytecode_bytes);

    // The AIR binds an additive u32-limb accumulator, not a hash of the event
    // list. Hashing here produced proofs that always failed verification with
    // OodEvaluationMismatch, which made `prove` and `run` unusable.
    let event_digest = bud_proof::event_digest_from_events(&receipt.events);

    // `initial_state_root` is the AIR's commitment to the state the program
    // started from, not the state tree root. It carries the memory image in
    // bytes 0..8 and the register file in bytes 8..16, both folded from what
    // the trace actually read. Passing `pre_root` here produced a value the
    // AIR compares against a fold it computes itself, so any run that seeded
    // memory or registers was unprovable and any run that seeded neither
    // happened to work because both sides were zero.
    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );

    let pi = ExecutionPublicInputs {
        chain_id: config.chain_id,
        program_hash: prog_hash,
        initial_state_root,
        final_state_root: post_root,
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest,
        state_writes_digest: [0u8; 32],
    };

    // Prove and Verify
    info!("Generating STARK proof...");
    let envelope = Prover::prove(&vm.trace, &pi, &config.bytecode)
        .map_err(|e| format!("Failed to generate proof: {:?}", e))?;
    info!(proof_bytes = envelope.proof_bytes.len(), "Proof generated");

    info!("Verifying proof...");
    let ok = Prover::verify(&envelope, &pi, &config.bytecode).is_ok();

    if !ok {
        if config.commit_state {
            state.rollback();
        }
        return Err("Verification of generated proof failed!".into());
    } else {
        if config.commit_state {
            state
                .commit()
                .map_err(|e| format!("Failed to commit transaction: {e}"))?;
        }
    }

    Ok(ExecutionOutput {
        pre_root,
        post_root,
        receipt,
        pi,
        envelope,
        state,
        vm,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Run {
            program,
            sender,
            nonce,
            block_height,
            args,
            json,
            proof_out,
            public_inputs_out,
            state_in,
            state_out,
        } => {
            let content = fs::read_to_string(program)
                .map_err(|e| format!("Failed to read program file: {e}"))?;

            #[cfg(feature = "experimental")]
            let profile = bud_isa::IsaProfile::Experimental;
            #[cfg(not(feature = "experimental"))]
            let profile = bud_isa::IsaProfile::Production;

            let bytecode = bud_compiler::compile(&content, profile)
                .map_err(|e| format!("Compilation failed: {e}"))?;

            let out = run_pipeline(ExecutionConfig {
                bytecode,
                sender: *sender,
                nonce: *nonce,
                block_height: *block_height,
                args: args.clone(),
                chain_id: cli.chain_id,
                state_in_file: state_in.clone(),
                commit_state: true,
            })?;

            // ATOMIC STATE SAVE
            let save_file = state_out
                .clone()
                .unwrap_or_else(|| state_in.clone().unwrap_or_else(|| "state.json".to_string()));
            out.state
                .save_to(&save_file)
                .map_err(|e| format!("Failed to save state: {e}"))?;

            if *json {
                let json_out = serde_json::json!({
                    "pre_state_root": hex::encode(out.pre_root),
                    "post_state_root": hex::encode(out.post_root),
                    "success": true,
                    "gas_used": out.receipt.gas_used,
                    "events": out.receipt.events,
                });
                println!("{}", serde_json::to_string_pretty(&json_out)?);
            } else {
                println!("Pre-state Root: {:?}", hex::encode(out.pre_root));
                println!("Post-state Root: {:?}", hex::encode(out.post_root));
                println!("Execution Trace Steps: {}", out.vm.trace.len());
                println!("Proof generated and verified successfully!");
            }

            if let Some(path) = proof_out {
                let data = serde_json::to_string_pretty(&out.envelope)
                    .map_err(|e| format!("Failed to serialize envelope: {e}"))?;
                fs::write(path, data).map_err(|e| format!("Failed to write proof file: {e}"))?;
                println!("Proof envelope written to {}", path);
            }

            if let Some(path) = public_inputs_out {
                let data = serde_json::to_string_pretty(&out.pi)
                    .map_err(|e| format!("Failed to serialize public inputs: {e}"))?;
                fs::write(path, data)
                    .map_err(|e| format!("Failed to write public inputs file: {e}"))?;
                println!("Public inputs written to {}", path);
            }
        }
        Commands::Prove {
            program,
            sender,
            nonce,
            block_height,
            args,
            proof_out,
            public_inputs_out,
        } => {
            let content = fs::read_to_string(program)
                .map_err(|e| format!("Failed to read program file: {e}"))?;
            #[cfg(feature = "experimental")]
            let profile = bud_isa::IsaProfile::Experimental;
            #[cfg(not(feature = "experimental"))]
            let profile = bud_isa::IsaProfile::Production;

            let bytecode = bud_compiler::compile(&content, profile)
                .map_err(|e| format!("Compilation failed: {e}"))?;

            let out = run_pipeline(ExecutionConfig {
                bytecode,
                sender: *sender,
                nonce: *nonce,
                block_height: *block_height,
                args: args.clone(),
                chain_id: cli.chain_id,
                state_in_file: None,
                commit_state: false,
            })?;

            let data = serde_json::to_string_pretty(&out.envelope)
                .map_err(|e| format!("Failed to serialize envelope: {e}"))?;
            fs::write(proof_out, data).map_err(|e| format!("Failed to write proof file: {e}"))?;
            println!("Proof written to: {}", proof_out);

            if let Some(path) = public_inputs_out {
                let data = serde_json::to_string_pretty(&out.pi)
                    .map_err(|e| format!("Failed to serialize public inputs: {e}"))?;
                fs::write(path, data)
                    .map_err(|e| format!("Failed to write public inputs file: {e}"))?;
                println!("Public inputs written to: {}", path);
            }
        }
        Commands::Batch {
            programs,
            sender,
            nonce,
            block_height,
            args,
        } => {
            println!("Processing batch of {} programs...", programs.len());
            let state_file = "state.json".to_string();
            for (index, p) in programs.iter().enumerate() {
                let content =
                    fs::read_to_string(p).map_err(|e| format!("Failed to read file {p}: {e}"))?;

                #[cfg(feature = "experimental")]
                let profile = bud_isa::IsaProfile::Experimental;
                #[cfg(not(feature = "experimental"))]
                let profile = bud_isa::IsaProfile::Production;

                let bytecode = bud_compiler::compile(&content, profile)
                    .map_err(|e| format!("Compilation of {p} failed: {e}"))?;

                let step_nonce = nonce.map(|n| n + index as u64);

                let out = run_pipeline(ExecutionConfig {
                    bytecode,
                    sender: *sender,
                    nonce: step_nonce,
                    block_height: *block_height,
                    args: args.clone(),
                    chain_id: cli.chain_id,
                    state_in_file: Some(state_file.clone()),
                    commit_state: true,
                })?;

                out.state.save_atomic().map_err(|e| {
                    format!("Failed to save state at batch step {}: {}", index + 1, e)
                })?;

                println!(
                    "Step {} [{}]: Executed, proved, verified, and state committed successfully. Post-state Root: {:?}",
                    index + 1,
                    p,
                    hex::encode(out.post_root)
                );
            }
        }
        Commands::Deploy { program, output } => {
            let content =
                fs::read_to_string(program).map_err(|e| format!("Failed to read file: {e}"))?;
            #[cfg(feature = "experimental")]
            let profile = bud_isa::IsaProfile::Experimental;
            #[cfg(not(feature = "experimental"))]
            let profile = bud_isa::IsaProfile::Production;

            let bytecode = bud_compiler::compile(&content, profile)
                .map_err(|e| format!("Compilation failed: {e}"))?;

            let out_name = output.clone().unwrap_or_else(|| format!("{program}.budc"));
            let bytes: Vec<u8> = bytecode
                .iter()
                .flat_map(|&val| val.to_le_bytes().to_vec())
                .collect();
            fs::write(&out_name, bytes).map_err(|e| format!("Failed to write output file: {e}"))?;
            println!("Deployed contract to {}", out_name);
        }
        Commands::Call {
            bytecode,
            sender,
            nonce,
            args,
        } => {
            let bytes = fs::read(bytecode).map_err(|e| format!("Failed to read bytecode: {e}"))?;
            if bytes.len() % 8 != 0 {
                return Err("Invalid bytecode: file size must be a multiple of 8 bytes".into());
            }
            let mut prog = Vec::new();
            for chunk in bytes.chunks_exact(8) {
                let mut b = [0u8; 8];
                b.copy_from_slice(chunk);
                prog.push(u64::from_le_bytes(b));
            }

            let out = run_pipeline(ExecutionConfig {
                bytecode: prog,
                sender: *sender,
                nonce: *nonce,
                block_height: None,
                args: args.clone(),
                chain_id: cli.chain_id,
                state_in_file: None,
                commit_state: true,
            })?;

            out.state
                .save()
                .map_err(|e| format!("Failed to save state: {e}"))?;
            println!(
                "Call success! Post-state Root: {:?}",
                hex::encode(out.post_root)
            );
        }
        Commands::Verify {
            proof_file,
            public_inputs_file,
            bytecode_file,
        } => {
            let env_data = fs::read_to_string(proof_file)
                .map_err(|e| format!("Failed to read proof file: {e}"))?;
            let envelope: ProofEnvelope = serde_json::from_str(&env_data)
                .map_err(|e| format!("Failed to parse proof envelope: {e}"))?;

            let pi_data = fs::read_to_string(public_inputs_file)
                .map_err(|e| format!("Failed to read public inputs file: {e}"))?;
            let expected_inputs: ExecutionPublicInputs = serde_json::from_str(&pi_data)
                .map_err(|e| format!("Failed to parse public inputs: {e}"))?;

            let bytes =
                fs::read(bytecode_file).map_err(|e| format!("Failed to read bytecode: {e}"))?;
            if bytes.len() % 8 != 0 {
                return Err("Invalid bytecode: file size must be a multiple of 8 bytes".into());
            }
            let mut program = Vec::new();
            for chunk in bytes.chunks_exact(8) {
                let mut b = [0u8; 8];
                b.copy_from_slice(chunk);
                program.push(u64::from_le_bytes(b));
            }

            match Prover::verify(&envelope, &expected_inputs, &program) {
                Ok(_) => {
                    println!("Result: VALID");
                }
                Err(e) => {
                    return Err(format!("Result: INVALID ({:?})", e).into());
                }
            }
        }
        Commands::Test => {
            let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
            let prog = vec![
                Instruction {
                    opcode: Opcode::Add,
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                    imm: 0,
                }
                .encode(),
                Instruction {
                    opcode: Opcode::Halt,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                }
                .encode(),
            ];
            vm.registers[2] = 10;
            vm.registers[3] = 20;
            let receipt = vm.run_receipt(&prog);
            if receipt.success {
                println!("Register 1: {}", vm.registers[1]);
            } else {
                println!("Test execution failed!");
            }
        }
    }

    Ok(())
}
