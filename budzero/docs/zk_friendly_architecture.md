# A ZK-friendly architecture

Our virtual machine runs smoothly and hands us an execution trace. Now we discuss how to turn that data into a matrix we can feed to a STARK prover. This is exactly where the mathematics and the engineering begin.

## An execution trace is a matrix

A ZK-STARK prover cannot read code. It only understands an enormous two-dimensional matrix full of numbers. The rows of that matrix are called **steps**, its columns **registers or state**.

For cryptographic reasons (FFT operations) the size of the matrix (the row count) must always be a **power of two** (16, 256, 1024, 65536 and so on).

### The traditional single-table approach (why is it bad?)

When first writing BudZKVM we tried putting the whole CPU state on every row:

- 1 column for `PC`
- 1 column for `Opcode`
- 32 columns for all the general-purpose registers (R0, R1 ... R31)

This approach makes the STARK proof very simple to write. You compare row $i$ with row $i+1$. If the opcode is `ADD R1, R2, R3` you check that R1 was updated **but the other 31 registers stayed the same**.

**The problem:** for the prover this is a terrible waste. In most operations (a JMP, say) no register changes at all, yet you still write 32 separate constraints saying "R0 did not change, R1 did not change... R31 did not change". The trace balloons, the prover slows down and it collapses from lack of memory.

### The solution: a multi-table, wide-trace architecture

Rather than holding the whole state in one table, we split the processor architecture into sub-parts (chiplets). BudZKVM applies this architecture (stage 2):

1. **The CPU table:** it holds only the values the current instruction reads and writes.
2. **The register table:** a separate area where all register accesses are ordered not chronologically but by register index.

In BudZKVM these two are joined side by side in a single matrix called the wide trace:

| CLK | PC | Opcode | ... CPU columns ... | REG_CLK | REG_IDX | REG_VAL | REG_IS_WRITE |
|---|---|---|---|---|---|---|---|
| 0 | 0 | Load | ... | 0 | 0 | 0 | 1 |
| 1 | 1 | Add | ... | 1 | 0 | 5 | 0 |
| 2 | 2 | Sub | ... | 4 | 0 | 15| 1 |
| ... | ... | ... | ... | 2 | 1 | 10| 0 |

*(Note that the register table on the right is ordered by register number (REG_IDX), not by time (CLK).)*

## Memory/register consistency

If the CPU table and the register table follow separate logics, how do we prove that the value the CPU read from $R1$ is the value $R1$ **really held** at that moment?

This is one of the most famous problems in the STARK world, and the solutions are the techniques called **permutation arguments** or **LogUp (fractional sums)**. BudZKVM chose **LogUp** for production-grade performance and security.

In short:

1. the CPU claims it read `5` from R1 and throws that claim into a "bus" pool,
2. the register table checks that R1 held `5` at that moment, confirms the operation and pulls it from the pool,
3. the LogUp mechanism accumulates these claims as fractional sums,
4. if the total comes out zero at the end of the day, the CPU and the register table are consistent. No value was created from nothing or lost.

## `COL_REG_SAME` and sub-clock ordering

One of the biggest obstacles in developing BudZKVM was read-after-write (RaW) ordering. If both a read and a write happen on the same clock cycle (for example `R1 = R1 + R2`), we must guarantee that the read comes **before** the write in the register table. To solve this we added a new parameter called `sub_clk` and updated the ordering to `(idx, clk, sub_clk)`.

We also created a helper boolean column called **COL_REG_SAME** to preserve the register table's integrity.

* If the next row points at the same register, `COL_REG_SAME = 1`.
* If the next row has moved to a new register (from R1 to R2, say), `COL_REG_SAME = 0`.

This simple trick dramatically lowered the degree of the transition constraints and let us obtain a performant prover.

We have laid out our architecture. But how are the mathematical formulas (the constraints) that check these tables' correctness turned into code? In the next chapter we write those equations (the AIR) with **STARK and Plonky3**.
