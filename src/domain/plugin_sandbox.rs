//! E3: Plugin Execution Sandbox and Isolation Layer.
//!
//! Enforces bounded execution budgets (gas and memory limits) and panic isolation
//! so custom domain plugins cannot cause Denial-of-Service or node crashes.

pub const DEFAULT_PLUGIN_GAS_LIMIT: u64 = 1_000_000;
pub const MAX_PLUGIN_MEMORY_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSandboxConfig {
    pub gas_limit: u64,
    pub max_memory_bytes: usize,
    pub allow_external_io: bool,
}

impl Default for PluginSandboxConfig {
    fn default() -> Self {
        Self {
            gas_limit: DEFAULT_PLUGIN_GAS_LIMIT,
            max_memory_bytes: MAX_PLUGIN_MEMORY_BYTES,
            allow_external_io: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    GasExhausted { used: u64, limit: u64 },
    MemoryLimitExceeded { requested: usize, limit: usize },
    ExecutionPanicked(String),
    DisallowedOperation(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GasExhausted { used, limit } => {
                write!(f, "Plugin gas exhausted: {used} > {limit}")
            }
            Self::MemoryLimitExceeded { requested, limit } => {
                write!(f, "Plugin memory limit exceeded: {requested} > {limit}")
            }
            Self::ExecutionPanicked(msg) => write!(f, "Plugin execution panicked: {msg}"),
            Self::DisallowedOperation(op) => {
                write!(f, "Plugin performed disallowed operation: {op}")
            }
        }
    }
}

impl std::error::Error for SandboxError {}

pub struct PluginSandbox {
    pub config: PluginSandboxConfig,
    pub gas_used: u64,
    pub memory_allocated: usize,
}

impl PluginSandbox {
    pub fn new(config: PluginSandboxConfig) -> Self {
        Self {
            config,
            gas_used: 0,
            memory_allocated: 0,
        }
    }

    pub fn charge_gas(&mut self, amount: u64) -> Result<(), SandboxError> {
        let new_gas = self.gas_used.saturating_add(amount);
        if new_gas > self.config.gas_limit {
            return Err(SandboxError::GasExhausted {
                used: new_gas,
                limit: self.config.gas_limit,
            });
        }
        self.gas_used = new_gas;
        Ok(())
    }

    pub fn allocate(&mut self, bytes: usize) -> Result<(), SandboxError> {
        let new_mem = self.memory_allocated.saturating_add(bytes);
        if new_mem > self.config.max_memory_bytes {
            return Err(SandboxError::MemoryLimitExceeded {
                requested: new_mem,
                limit: self.config.max_memory_bytes,
            });
        }
        self.memory_allocated = new_mem;
        Ok(())
    }

    /// Execute a pure closure within safe panic and resource boundaries.
    pub fn run_isolated<F, R>(&mut self, f: F) -> Result<R, SandboxError>
    where
        F: FnOnce(&mut Self) -> Result<R, SandboxError> + std::panic::UnwindSafe,
    {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self))).map_err(|e| {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            SandboxError::ExecutionPanicked(msg)
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_exhaustion_is_enforced() {
        let mut sandbox = PluginSandbox::new(PluginSandboxConfig {
            gas_limit: 100,
            max_memory_bytes: 1024,
            allow_external_io: false,
        });
        assert!(sandbox.charge_gas(50).is_ok());
        assert!(sandbox.charge_gas(60).is_err());
    }

    #[test]
    fn panic_is_caught_and_isolated() {
        let mut sandbox = PluginSandbox::new(PluginSandboxConfig::default());
        let res = sandbox.run_isolated(|_| -> Result<(), SandboxError> {
            panic!("fatal plugin bug");
        });
        assert!(matches!(res, Err(SandboxError::ExecutionPanicked(_))));
    }
}
