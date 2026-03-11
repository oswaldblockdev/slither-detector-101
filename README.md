# Slither-Detector-101 🕵️‍♂️

Welcome to the **Slither-Detector-101** tutorial series. This repository is designed to teach you how to write custom static analysis detectors for Ethereum Smart Contracts using the [Slither](https://github.com/crytic/slither) framework.

## 🏗️ Core Concepts

Before diving into the levels, it is essential to understand the hierarchy Slither uses to represent a contract. Your detectors will navigate this tree:

* **Contract:** The top-level object containing functions and state variables.
* **Function:** Contains visibility, modifiers, and a list of Nodes.
* **Node:** An individual line or control flow statement (if, loop, expression).
* **SlithIR:** The Intermediate Representation where high-level Solidity is broken down into simplified instructions (e.g., `HighLevelCall`, `BinaryOp`).

---

## 🚀 The 10-Level Roadmap

This outline moves from basic metadata filtering to complex data-flow and dependency analysis.

### Level 1: The "Hello World" (Metadata)

**Objective:** Find functions with specific names.

* **Learning:** Iterating through `contract.functions`.
* **Task:** Flag any function named `debug_kill()` or `test_reset()` left in production.

### Level 2: Visibility & Authorization

**Objective:** Identify unprotected entry points.

* **Learning:** Checking `f.visibility` and `f.modifiers`.
* **Task:** Flag `public`/`external` functions that modify state but lack an `onlyOwner` or `onlyRole` modifier.

### Level 3: Gas Exhaustion Patterns

**Objective:** Find loops prone to DoS.

* **Learning:** Identifying dynamic loop size.
* **Task:** Detect `for` loops that iterate over a dynamic array length (e.g., `users.length`).

### Level 4: Event Emission Tracking

**Objective:** Ensure state changes are logged.

* **Learning:** Using `function.state_variables_written`.
* **Task:** Flag functions that update a `balance` mapping without emitting a corresponding `Transfer` or `Update` event.

### Level 5: Interface Compliance

**Objective:** Validate standard implementation.

* **Learning:** Comparing function signatures and return types.
* **Task:** Verify if a contract claiming to be ERC20 implements `transfer` with the correct `bool` return type.

---

### Level 6: SlithIR Deep Dive

**Objective:** Analyze low-level operations.

* **Learning:** Iterating through `node.irs` (Intermediate Representation).
* **Task:** Detect the use of the `SELFDESTRUCT` opcode(`SOLIDITY_CALL selfdestruct(address)` in slitherIR), regardless of the variable names used in Solidity.

### Level 7: Guard Rail Logic

**Objective:** Analyze function requirements.

* **Learning:** Filtering nodes for `SolidityCall` to `require()` or `revert()`.
* **Task:** Flag functions that perform an external `call` without a preceding `require()` check.

### Level 8: Reentrancy Primitives

**Objective:** Identify "Check-Effects-Interactions" violations.

* **Learning:** Sequencing `HighLevelCall` vs. `StateVariableWrite`.
* **Task:** Alert if a state variable is written to *after* an external call occurs within the same function.

### Level 9: Taint Analysis (Data Dependency)

**Objective:** Track user input to sensitive sinks.

* **Learning:** Using `Slither.context` and `is_dependent()`.
* **Task:** Determine if a user-provided `address` argument is used as the target of a `low_level_call`.

### Level 10: Cross-Function Data Flow

**Objective:** Detect vulnerabilities spanning multiple calls.

* **Learning:** Advanced state-tracking across the contract.
* **Task:** Identify uninitialized proxy vulnerabilities where a global `initialized` boolean is not checked in a sensitive `setup()` function.

---

## 🛠️ How to use this Repo

1. **Explore:** Each folder `level-0x` contains a `detector.py` and a `vulnerable.sol`.
2. **Run:** Execute the detector using:
```bash
uv run ./level-01-metadata/detector.py
```

3. **Debug:** Use `slither-read-contract vulnerable.sol --print nodes` to see the IR tree.