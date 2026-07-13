# AgentController Refactoring Design

## Overview
The `AgentController` currently acts as a monolithic "God Class" that manages LLM execution, lifecycle state (pause/resume), CTF flag detection, and event pub/sub. This design decouples these concerns into a clean Facade pattern, distributing responsibilities to specific manager classes.

## Architecture

We will implement a **Composition/Facade Pattern**, introducing two new internal components while keeping `AgentController` as the public entry point.

### 1. `LifecycleManager` (New: `pentestgpt/core/lifecycle.py`)
- **Purpose**: Encapsulates the agent's state machine (`AgentState`) and async blocking primitives.
- **State**: Holds `_state`, `_pause_requested`, `_stop_requested`, `_resume_event`, and `_pending_instruction`.
- **Key Methods**:
  - `pause()`, `resume()`, `stop()`, `inject()`
  - `wait_if_paused()`: Handles the `asyncio.Event` wait loop and yields execution back if resumed/stopped.
  - `set_state()`: Transitions state and fires corresponding lifecycle events.

### 2. `MessageProcessor` (New: `pentestgpt/core/processing.py`)
- **Purpose**: Evaluates `AgentMessage` streams, extracts CTF flags, and coordinates data storage.
- **Responsibilities**:
  - Parsing message text for CTF flags (`_detect_flags`).
  - Emitting specific UI events (e.g., `emit_tool_start`, `emit_flag`) via `EventBus`.
  - Updating the `SessionStore` with new costs, flags, and instructions.
- **Key Methods**:
  - `process_message(msg: AgentMessage, session_store: SessionStore, events: EventBus)`

### 3. `AgentController` (Modified: `pentestgpt/core/controller.py`)
- **Purpose**: The main loop orchestrator and Facade API.
- **Changes**:
  - Composes instances of `LifecycleManager` and `MessageProcessor`.
  - Delegates all pause/resume requests to `LifecycleManager`.
  - The `run()` method becomes a clean, linear loop:
    1. Check `lifecycle.is_stopped()`.
    2. Check `lifecycle.wait_if_paused()`.
    3. Pass LLM responses to `MessageProcessor.process_message()`.

## Data Flow
1. **User Action**: User clicks "Pause" in TUI -> Calls `AgentController.pause()` -> Delegates to `LifecycleManager.pause()`.
2. **LLM Output**: `backend.receive_messages()` yields `msg` -> `MessageProcessor.process_message(msg)` -> Extracts flag, emits event, saves to session.

## Testing Strategy
- Existing integration tests (e.g. `test_agent_controller.py`) should continue to pass with zero modifications since `AgentController` retains its public API signature.
- New unit tests can be written for `LifecycleManager` independently of LLM/EventBus infrastructure.
