# AWS Strands Agents SDK - Comprehensive Research

**Package**: `strands-agents` (v1.27.0 as of Feb 19, 2026)
**License**: Apache 2.0
**Author**: AWS
**Python**: >= 3.10
**Repo**: https://github.com/strands-agents/sdk-python
**Docs**: https://strandsagents.com
**SDKs**: Python and TypeScript

---

## 1. What is Strands Agents?

Strands Agents is an **open-source SDK from AWS** for building production-ready AI agents using a **model-driven approach**. The core philosophy is that the LLM itself drives orchestration -- deciding which tools to call, when, and how to synthesize results -- rather than relying on rigid developer-defined control flow.

**Key characteristics:**
- **Minimal boilerplate**: A working agent can be created in 3 lines of code
- **Model-agnostic**: Supports 12+ model providers (Bedrock, Anthropic, OpenAI, Gemini, Ollama, etc.)
- **AWS-native**: Deep integration with Bedrock, AgentCore, Lambda, EKS, Fargate
- **Production-grade**: Built-in observability (OpenTelemetry), guardrails, session management, retry strategies
- **Multi-agent**: First-class support for Swarm, Graph, and Agent-to-Agent patterns

---

## 2. Installation

```bash
pip install strands-agents strands-agents-tools
```

The `strands-agents` package is the core SDK. The `strands-agents-tools` package provides 50+ pre-built tools (calculator, file operations, HTTP requests, memory, shell, etc.).

**Default**: Uses Amazon Bedrock with Claude Sonnet in us-west-2. Requires AWS credentials configured (e.g., via `aws configure` or environment variables).

---

## 3. Core Architecture: The Agent Loop

The fundamental execution pattern is an **event loop** that cycles between LLM reasoning and tool execution:

```
User Input
    |
    v
+-------------------+
| Agent Loop Start  |
+-------------------+
    |
    v
+-------------------+
| LLM Inference     |  <-- Model reasons about input + available tools
+-------------------+
    |
    v
+-------------------+
| Stop Reason?      |
+-------------------+
    |           |            |
    v           v            v
 "end_turn"  "tool_use"  "max_tokens"
 (return)    (execute)    (error)
                |
                v
        +-------------------+
        | Execute Tool(s)   |
        +-------------------+
                |
                v
        +-------------------+
        | Append Results    |
        +-------------------+
                |
                v
        (Loop back to LLM Inference)
```

### Event Loop Details (`event_loop_cycle`)

The core function `event_loop_cycle` is an async generator that:

1. **Checks interrupt state** - skips model call if resuming from an interrupt
2. **Calls the model** - with retry logic (max 6 attempts, exponential backoff 4-240s)
3. **Processes stop reason**:
   - `"end_turn"`: Returns the response (or forces structured output if needed)
   - `"tool_use"`: Validates tools, executes them, appends results, recurses
   - `"max_tokens"`: Raises `MaxTokensReachedException`
4. **Handles errors**:
   - `ContextWindowOverflowException` triggers `conversation_manager.reduce_context()`
   - Model execution errors trigger `ForceStopEvent`

### Event Loop Source Modules

```
strands/event_loop/
├── __init__.py
├── event_loop.py                          # Core event_loop_cycle() function
├── streaming.py                           # Streaming event processing
├── _retry.py                              # ModelRetryStrategy implementation
└── _recover_message_on_max_tokens_reached.py  # Token limit recovery
```

### Termination Conditions
- Model returns `end_turn` stop reason
- Tool execution sets `stop_event_loop` flag
- Structured output successfully extracted
- User interrupt triggered
- Max tokens reached

---

## 4. The Agent Class - Core API

### Constructor

```python
from strands import Agent

agent = Agent(
    # Model configuration
    model=None,                          # Model instance or string; defaults to BedrockModel

    # Tools
    tools=None,                          # List of tools (decorated functions, AgentTool, ToolProvider, etc.)
    load_tools_from_directory=False,     # Auto-load from ./tools/ directory
    tool_executor=None,                  # Custom tool execution strategy

    # Prompts
    system_prompt=None,                  # System prompt string or list of content blocks
    structured_output_model=None,        # Pydantic BaseModel for structured output
    structured_output_prompt=None,       # Custom prompt for structured output extraction

    # Conversation management
    messages=None,                       # Initial message history
    conversation_manager=None,           # Defaults to SlidingWindowConversationManager(window_size=40)

    # Lifecycle & observability
    callback_handler=None,              # Streaming callback handler
    hooks=None,                          # List of HookProvider instances
    plugins=None,                        # List of Plugin instances
    trace_attributes=None,              # OpenTelemetry trace attributes

    # Identity
    agent_id=None,                       # Unique agent identifier
    name=None,                           # Human-readable name (defaults to "Strands Agents")
    description=None,                    # Agent description (used in multi-agent)

    # State & sessions
    state=None,                          # AgentState or dict for agent-specific data
    session_manager=None,                # SessionManager for persistence

    # Execution
    tool_executor=None,                  # Custom ToolExecutor (concurrent or sequential)
    retry_strategy=None,                 # ModelRetryStrategy instance (default: 6 attempts, 4-240s)
    concurrent_invocation_mode="THROW",  # How to handle concurrent calls ("throw" or "unsafe_reentrant")

    record_direct_tool_call=True,        # Record direct tool calls in history
)
```

### Invocation Methods

```python
# Synchronous call (most common) - returns AgentResult
result = agent("What is 2 + 2?")

# With invocation state (passed to tools via ToolContext)
result = agent("Analyze this", invocation_state={"user_id": "abc123", "api_key": "sk-..."})

# Async invocation
result = await agent.invoke_async("What is 2 + 2?")

# Async streaming - yields events progressively
async for event in agent.stream_async("What is 2 + 2?"):
    print(event)

# Structured output (returns Pydantic model)
from pydantic import BaseModel

class Answer(BaseModel):
    value: int
    explanation: str

result = agent("What is 2 + 2?", structured_output_model=Answer)
parsed = result.structured_output  # Answer(value=4, explanation="...")
```

### AgentResult

```python
result = agent("Hello")
result.stop_reason         # "end_turn", "max_tokens", "tool_use", etc.
result.message             # Final model response message
result.metrics             # Performance data
result.state               # Final event loop state
result.structured_output   # Parsed Pydantic model (if structured_output_model was set)
```

### Key Properties

```python
agent.tool_names      # List of registered tool names
agent.tools           # ToolRegistry instance
agent.messages        # Conversation history
agent.state           # AgentState dict-like object
agent.name            # Agent name
agent.tool.my_tool()  # Direct tool invocation via _ToolCaller
```

---

## 5. Tools - Definition and Usage

### 5.1 The @tool Decorator (Primary Pattern)

```python
from strands import tool

@tool
def weather(city: str, units: str = "celsius") -> dict:
    """Get the current weather for a city.

    Args:
        city: The city name to look up weather for.
        units: Temperature units - 'celsius' or 'fahrenheit'.
    """
    data = fetch_weather(city, units)
    return {
        "status": "success",
        "content": [{"text": f"Weather in {city}: {data['temp']}deg {units}"}]
    }
```

**How it works internally (FunctionToolMetadata -> DecoratedFunctionTool):**
1. The decorator extracts the function name as the tool name
2. The docstring becomes the tool description (LLM uses this to understand the tool)
3. Type hints are converted to JSON Schema via Pydantic model generation
4. The `Args:` section in the docstring provides parameter descriptions
5. Return values are automatically wrapped in the standard tool result format
6. The function is wrapped in a `DecoratedFunctionTool` implementing the `AgentTool` interface

**Generated tool spec structure:**
```python
{
    "name": "weather",
    "description": "Get the current weather for a city.",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "The city name to look up weather for."},
                "units": {"type": "string", "description": "Temperature units - 'celsius' or 'fahrenheit'.", "default": "celsius"}
            },
            "required": ["city"]
        }
    }
}
```

### 5.2 Decorator Parameters

```python
@tool(
    name="custom_tool_name",          # Override function name
    description="Custom description",  # Override docstring
    inputSchema={...},                 # Custom JSON Schema (bypasses auto-generation)
    context=True,                      # Inject ToolContext as 'tool_context' parameter
    # context="my_ctx"                 # Or use a custom parameter name
)
def my_tool(param1: str, tool_context: ToolContext) -> dict:
    ...
```

### 5.3 Using Annotated Types for Parameter Descriptions

```python
from typing import Annotated
from strands import tool

@tool
def search(
    query: Annotated[str, "The search query to execute"],
    max_results: Annotated[int, "Maximum number of results to return"] = 10
) -> dict:
    """Search the knowledge base."""
    ...
```

### 5.4 Tool Context - Accessing Agent State

```python
from strands import tool, ToolContext

@tool(context=True)
def stateful_tool(query: str, tool_context: ToolContext = None) -> dict:
    """A tool that accesses agent context."""

    # Access the tool invocation details
    tool_use_id = tool_context.tool_use["toolUseId"]
    tool_name = tool_context.tool_use["name"]
    tool_input = tool_context.tool_use["input"]

    # Access the agent instance
    agent = tool_context.agent
    messages = agent.messages  # Full conversation history
    state = agent.state        # Agent state dict

    # Access invocation state (kwargs from agent.__call__)
    inv_state = tool_context.invocation_state
    api_key = inv_state.get("api_key", "")

    return {"status": "success", "content": [{"text": "Done"}]}
```

**ToolContext dataclass:**
```python
@dataclass
class ToolContext:
    tool_use: ToolUse              # Tool invocation details (toolUseId, name, input)
    agent: Any                     # The Agent instance executing this tool
    invocation_state: dict[str, Any]  # Caller-provided kwargs from agent invocation
```

### 5.5 Tool Result Format

Tools can return results in several ways:

```python
# Option 1: Standard dict format (most explicit)
return {
    "status": "success",  # or "error"
    "content": [
        {"text": "Result text here"},
        {"json": {"key": "value"}},
        {"image": image_content},
        {"document": doc_content}
    ]
}

# Option 2: Simple return (auto-wrapped by decorator)
return "Result text"
return 42
return {"key": "value"}

# Option 3: For errors
return {
    "status": "error",
    "content": [{"text": "Error message here"}]
}
```

### 5.6 Registering Tools with an Agent

```python
from strands import Agent, tool
from strands_tools import calculator

@tool
def my_custom_tool(input: str) -> str:
    """My custom tool."""
    return f"Processed: {input}"

# Pass tools as a list
agent = Agent(tools=[calculator, my_custom_tool])

# Or load from directory
agent = Agent(load_tools_from_directory=True)  # Loads from ./tools/
```

**Accepted tool formats:**
- `@tool` decorated functions (DecoratedFunctionTool)
- `AgentTool` instances
- `ToolProvider` instances (e.g., MCPClient)
- File paths to Python modules
- Dictionaries with `name`/`path` keys
- Module import strings

### 5.7 Dynamic Tool Registration at Runtime

```python
agent = Agent(tools=[tool1])

# Add tools dynamically
agent.tools.register_dynamic_tool(new_tool)

# Replace a tool implementation
agent.tools.replace(updated_tool)

# Reload from disk (hot-reload)
agent.tools.reload_tool("tool_name")

# Get all tool configurations (for sending to model)
configs = agent.tools.get_all_tools_config()
```

### 5.8 MCP (Model Context Protocol) Tools

```python
from strands import Agent
from strands.tools.mcp import MCPClient
from mcp import stdio_client, StdioServerParameters

# Connect to an MCP server
mcp_client = MCPClient(
    transport_callable=lambda: stdio_client(StdioServerParameters(
        command="uvx",
        args=["awslabs.aws-documentation-mcp-server@latest"]
    )),
    startup_timeout=30,
)

# Use as context manager
with mcp_client:
    tools = mcp_client.load_tools()
    agent = Agent(tools=tools)
    result = agent("Tell me about Amazon Bedrock")

# Or with tool filters and prefix
mcp_client = MCPClient(
    transport_callable=...,
    tool_filters={
        "allowed": ["search_*", "read_*"],
        "rejected": ["delete_*", "admin_*"],
    },
    prefix="docs",  # Prefix tool names to avoid conflicts
)
```

### 5.9 AgentTool Interface (For Custom Tool Classes)

```python
from strands.types.tools import AgentTool

class AgentTool(ABC):
    @property
    @abstractmethod
    def tool_name(self) -> str: ...

    @property
    @abstractmethod
    def tool_spec(self) -> dict: ...

    @property
    @abstractmethod
    def tool_type(self) -> str: ...  # "function", "python", "lambda", etc.

    @abstractmethod
    def stream(self, tool_use, invocation_state, **kwargs) -> Generator: ...

    def supports_hot_reload(self) -> bool: return False
    def is_dynamic(self) -> bool: ...
    def mark_dynamic(self) -> None: ...
    def get_display_properties(self) -> dict: ...
```

---

## 6. Model Providers

### 6.1 Amazon Bedrock (Default)

```python
from strands import Agent
from strands.models.bedrock import BedrockModel

model = BedrockModel(
    model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
    region_name="us-east-1",           # Defaults to AWS_REGION env var or "us-west-2"
    max_tokens=4096,
    temperature=0.3,
    top_p=0.9,
    # streaming=True,                  # Default: True (uses converse_stream API)
    # stop_sequences=["\n\nHuman:"],
    # boto_session=boto3.Session(),    # Custom boto3 session
    # boto_client_config=BotocoreConfig(),  # Custom client config
    # endpoint_url="https://...",      # VPC/PrivateLink endpoint
    # Guardrails
    # guardrail_id="my-guardrail-id",
    # guardrail_version="1",
    # Caching
    # cache_config={"strategy": "auto"},
    # tool_choice={"auto": {}},        # or {"any": {}} or {"tool": {"name": "..."}}
)

agent = Agent(model=model)
```

**Bedrock streaming modes:**
- **Streaming (default):** Calls `converse_stream()` API, processes chunks sequentially
- **Non-streaming:** Calls `converse()` API, converts to streaming format for consistency

### 6.2 Anthropic Direct

```python
from strands.models.anthropic import AnthropicModel

model = AnthropicModel(
    client_args={"api_key": "sk-ant-..."},  # Passed to anthropic.AsyncAnthropic()
    model_id="claude-sonnet-4-20250514",    # Required
    max_tokens=4096,                         # Required
    params={"temperature": 0.7},             # Additional model params
)
agent = Agent(model=model)
```

### 6.3 OpenAI

```python
from strands.models.openai import OpenAIModel

model = OpenAIModel(
    client_args={"api_key": "sk-..."},  # Passed to openai.AsyncOpenAI()
    # Or: client=pre_configured_openai_client,  # Reuse existing client
    model_id="gpt-4o",                  # Required
    params={"max_tokens": 4096},        # Additional params
)
agent = Agent(model=model)
```

### 6.4 Ollama (Local)

```python
from strands.models.ollama import OllamaModel

model = OllamaModel(
    model_id="llama3",
    host="http://localhost:11434",
)
agent = Agent(model=model)
```

### 6.5 LiteLLM (Multi-Provider Abstraction)

```python
from strands.models.litellm import LiteLLMModel

model = LiteLLMModel(model_id="anthropic/claude-sonnet-4-20250514")
agent = Agent(model=model)
```

**All supported providers**: Bedrock, Anthropic, OpenAI, Gemini, Ollama, LlamaCPP, LlamaAPI, LiteLLM, Mistral, Writer, SageMaker.

**All models implement a common interface:**
- `format_request()` - Convert messages to provider-specific format
- `stream()` - Async streaming from the model
- `structured_output()` - Structured output via tool calls
- `update_config()` / `get_config()` - Runtime configuration changes

---

## 7. Multi-Agent Orchestration

Strands provides three built-in multi-agent patterns plus the ability to use agents as tools.

### Public API Exports

```python
from strands.multiagent import (
    GraphBuilder,        # Fluent graph construction
    GraphResult,         # Result from graph execution
    MultiAgentBase,      # Base class for multi-agent systems
    MultiAgentResult,    # Result container
    Status,              # PENDING, EXECUTING, COMPLETED, FAILED, INTERRUPTED
    Swarm,               # Swarm coordination
    SwarmResult,         # Result from swarm execution
)
```

### 7.1 Agents as Tools (Simplest Pattern)

The simplest multi-agent pattern: wrap an agent as a tool callable by another agent.

```python
from strands import Agent, tool

# Create specialist agents
researcher = Agent(
    name="researcher",
    system_prompt="You are a research specialist. Find information thoroughly.",
    tools=[search_tool, web_scraper]
)

writer = Agent(
    name="writer",
    system_prompt="You are a technical writer. Write clear, concise content.",
    tools=[]
)

# Wrap agents as tools
@tool
def research(query: str) -> str:
    """Research a topic thoroughly and return findings."""
    result = researcher(query)
    return str(result)

@tool
def write_content(topic: str, research_notes: str) -> str:
    """Write polished content based on research notes."""
    result = writer(f"Write about {topic}. Research notes: {research_notes}")
    return str(result)

# Orchestrator agent uses specialist agents as tools
orchestrator = Agent(
    system_prompt="You coordinate research and writing tasks.",
    tools=[research, write_content]
)

result = orchestrator("Write a blog post about quantum computing")
```

### 7.2 Swarm Pattern

A self-organizing system where agents autonomously hand off tasks to each other. Each agent gets a `handoff_to_agent` tool injected automatically.

```python
from strands import Agent
from strands.multiagent import Swarm

# Define specialist agents
triage_agent = Agent(
    name="triage",
    description="Routes customer queries to the right specialist",
    system_prompt="You are a triage agent. Route queries to the appropriate specialist.",
    tools=[classify_intent]
)

billing_agent = Agent(
    name="billing",
    description="Handles billing questions, refunds, and payment issues",
    system_prompt="You are a billing specialist.",
    tools=[lookup_invoice, process_refund]
)

technical_agent = Agent(
    name="technical",
    description="Handles technical support and troubleshooting",
    system_prompt="You are a technical support specialist.",
    tools=[check_system_status, run_diagnostics]
)

# Create the swarm
swarm = Swarm(
    nodes=[triage_agent, billing_agent, technical_agent],
    entry_point=triage_agent,           # Starting agent (defaults to first)
    max_handoffs=20,                     # Limit handoff chains
    max_iterations=20,                   # Limit total iterations
    execution_timeout=900.0,             # 15 minute total timeout
    node_timeout=300.0,                  # 5 minute per-node timeout
    repetitive_handoff_detection_window=0,  # Detect loops (0 = disabled)
    # session_manager=session_mgr,       # Optional persistence
    # hooks=[my_hook],                   # Optional event hooks
)

# Execute
result = swarm("I was charged twice for my subscription last month")
# or async
result = await swarm.invoke_async("I was charged twice")
# or streaming
async for event in swarm.stream_async("I was charged twice"):
    pass
```

**How Swarm Works:**
1. Entry_point agent receives the task
2. Each agent gets a `handoff_to_agent(agent_name, message, context)` tool injected automatically
3. Agents autonomously decide when to hand off and to whom
4. SharedContext flows between agents (agents contribute via `add_context(key, value)`)
5. The swarm terminates when an agent completes without handing off

**Key Swarm Internal Classes:**
- `SwarmNode`: Wraps an Agent with node_id, reference to swarm, and reset capability
- `SharedContext`: Key-value store shared across all agents in the swarm
- `SwarmState`: Tracks current_node, task, completion_status, node_history, accumulated_usage

**Termination conditions:**
- Agent completes without handoff
- Max handoffs/iterations exceeded
- Execution timeout reached
- Repetitive handoff pattern detected
- User interrupt

### 7.3 Graph Pattern

Directed graph orchestration with parallel execution, conditional routing, and dependency management.

```python
from strands import Agent
from strands.multiagent import GraphBuilder

# Create agents
planner = Agent(name="planner", system_prompt="Create a detailed plan.", tools=[])
researcher = Agent(name="researcher", system_prompt="Research thoroughly.", tools=[search])
analyst = Agent(name="analyst", system_prompt="Analyze data.", tools=[analyze])
writer = Agent(name="writer", system_prompt="Write the final report.", tools=[])

# Build the graph
builder = GraphBuilder()

# Add nodes (executor can be Agent or MultiAgentBase - nesting is supported!)
builder.add_node(planner, node_id="plan")
builder.add_node(researcher, node_id="research")
builder.add_node(analyst, node_id="analyze")
builder.add_node(writer, node_id="write")

# Define edges (with optional conditions)
builder.add_edge("plan", "research")       # plan -> research
builder.add_edge("plan", "analyze")        # plan -> analyze (parallel with research)
builder.add_edge("research", "write")      # research -> write
builder.add_edge("analyze", "write")       # analyze -> write (waits for BOTH)

# Conditional edge (cycles back if analysis is insufficient)
def needs_more_research(state):
    return "insufficient" in str(state.results.get("analyze", ""))

builder.add_edge("analyze", "research", condition=needs_more_research)

# Configure
builder.set_entry_point("plan")
builder.set_max_node_executions(50)
builder.set_execution_timeout(600.0)
# builder.set_node_timeout(300.0)         # Per-node timeout
# builder.set_reset_on_revisit(True)      # Stateless re-execution

# Build and execute
graph = builder.build()
result = await graph.invoke_async("Analyze the impact of AI on healthcare")
```

**How Graph Works:**
1. Entry point nodes execute first
2. Downstream nodes activate when ALL dependencies complete AND edge conditions are met
3. Independent nodes execute in **parallel** (asyncio queue-based batch processing)
4. Results from parent nodes are formatted and passed as input to children:
   ```
   "Original Task: [task]
   Inputs from previous nodes:
   From plan: [plan output]
   From research: [research output]"
   ```
5. Supports cycles (via conditional edges) for iterative workflows

**Key Graph Internal Classes:**
- `GraphNode`: Wraps executor (Agent or MultiAgentBase) with dependencies, status, and result
- `GraphEdge`: Connects nodes with optional `condition: Callable[[GraphState], bool]`
- `GraphState`: Tracks task, status, completed/failed/interrupted nodes, results, metrics
- `GraphBuilder`: Fluent API for construction

### 7.4 Composable Multi-Agent

Graph nodes can contain Swarms, Swarm nodes can contain Graphs, etc. The `MultiAgentBase` interface ensures composability:

```python
class MultiAgentBase(ABC):
    id: str

    @abstractmethod
    async def invoke_async(self, task, invocation_state=None, **kwargs) -> MultiAgentResult: ...

    async def stream_async(self, task, invocation_state=None, **kwargs) -> AsyncIterator: ...

    def __call__(self, task, **kwargs) -> MultiAgentResult: ...  # Sync wrapper

    def serialize_state(self) -> dict: ...     # For persistence
    def deserialize_state(self, data) -> None: ...
```

```python
# NodeResult wraps individual node execution results
@dataclass
class NodeResult:
    result: AgentResult | MultiAgentResult | Exception
    execution_time: float
    status: Status
    accumulated_usage: dict
    accumulated_metrics: dict

# MultiAgentResult wraps the entire multi-agent execution
@dataclass
class MultiAgentResult:
    status: Status
    results: dict[str, NodeResult]
    accumulated_usage: dict
    accumulated_metrics: dict

# Status enum
class Status(Enum):
    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
```

---

## 8. Conversation Management

### SlidingWindowConversationManager (Default)

```python
from strands.agent.conversation_manager import SlidingWindowConversationManager

manager = SlidingWindowConversationManager(
    window_size=40,              # Max messages to keep
    should_truncate_results=True, # Truncate oversized tool results
    per_turn=False,              # Apply management during execution (False/True/int)
)

agent = Agent(conversation_manager=manager)
```

**How it works:**
- When messages exceed `window_size`, oldest messages are trimmed
- Maintains tool use/result pair consistency (won't orphan a toolUse without its toolResult)
- `per_turn=True` applies context management before each model call (proactive)
- `per_turn=5` applies every 5 model calls

### Other Managers
- **NullConversationManager**: No context management (keeps everything)
- **SummarizingConversationManager**: Summarizes old messages instead of removing them

---

## 9. Session Persistence

### SessionManager Interface

All session managers implement a hook-based system:

```python
class SessionManager(HookProvider, ABC):
    # Called via AgentInitializedEvent hook
    def initialize(self, agent: Agent) -> None: ...

    # Called via MessageAddedEvent hook
    def append_message(self, message: Message, agent: Agent) -> None: ...

    # Called via MessageAddedEvent and AfterInvocationEvent hooks
    def sync_agent(self, agent: Agent) -> None: ...

    # Called for guardrail redaction
    def redact_latest_message(self, redact_message: Message, agent: Agent) -> None: ...

    # Multi-agent support (optional)
    def sync_multi_agent(self, ...) -> None: ...
    def initialize_multi_agent(self, ...) -> None: ...
```

### FileSessionManager (Local)

```python
from strands.session.file_session_manager import FileSessionManager

session_mgr = FileSessionManager(
    session_id="my-session-123",
    storage_dir="/tmp/strands/sessions",  # Optional, defaults to temp dir
)

agent = Agent(
    system_prompt="You are a helpful assistant.",
    session_manager=session_mgr,
    agent_id="agent-1",
)

# First conversation
agent("My name is Alice")

# Later - state is automatically restored when agent initializes
agent2 = Agent(
    system_prompt="You are a helpful assistant.",
    session_manager=FileSessionManager(session_id="my-session-123"),
    agent_id="agent-1",
)
agent2("What is my name?")  # Remembers "Alice"
```

**File structure on disk (atomic writes via temp files):**
```
/storage_dir/
└── session_<id>/
    ├── session.json
    ├── agents/
    │   └── agent_<id>/
    │       ├── agent.json
    │       └── messages/
    │           ├── message_0.json
    │           └── message_1.json
    └── multi_agents/
        └── multi_agent_<id>/
            └── multi_agent.json
```

### S3SessionManager (Cloud)

```python
from strands.session.s3_session_manager import S3SessionManager

session_mgr = S3SessionManager(
    session_id="my-session-123",
    # S3 bucket and prefix configuration
)
```

### RepositorySessionManager (Git-based)

```python
from strands.session.repository_session_manager import RepositorySessionManager

session_mgr = RepositorySessionManager(
    session_id="my-session-123",
    # Repository configuration
)
```

---

## 10. Callback Handlers and Streaming

### Built-in Callback Handlers

```python
from strands.handlers.callback_handler import (
    PrintingCallbackHandler,    # Streams text to stdout (default)
    CompositeCallbackHandler,   # Combines multiple handlers
    null_callback_handler,      # Discards all output (no-op function)
)
```

### PrintingCallbackHandler

```python
# Default behavior - prints streamed text and announces tool invocations
agent = Agent(callback_handler=PrintingCallbackHandler(verbose_tool_use=True))
```

The callback receives kwargs:
- `reasoningText` (str | None): Extended thinking / reasoning content
- `data` (str): Text content being streamed
- `complete` (bool): Whether this is the final chunk
- `event` (dict): ModelStreamChunkEvent data

### Custom Callback Handler

Any callable accepting `**kwargs` works as a callback handler:

```python
def my_callback(**kwargs):
    if "reasoningText" in kwargs and kwargs["reasoningText"]:
        print(f"[THINKING] {kwargs['reasoningText']}", end="")
    if "data" in kwargs:
        print(f"{kwargs['data']}", end="", flush=True)
    if kwargs.get("complete"):
        print("\n--- Done ---")

agent = Agent(callback_handler=my_callback)
```

### Composite Handler

```python
handler = CompositeCallbackHandler(
    PrintingCallbackHandler(),
    my_logging_handler,
    my_metrics_handler,
)
agent = Agent(callback_handler=handler)
```

### Silent Agent (No Output)

```python
agent = Agent(callback_handler=None)  # Uses null_callback_handler internally
```

### Async Streaming

```python
async for event in agent.stream_async("Tell me a story"):
    # Events include text chunks, tool use events, and final AgentResultEvent
    pass
```

---

## 11. Hook System (Lifecycle Events)

Hooks allow you to observe and modify agent behavior at key lifecycle points.

### Available Events

| Event | When it Fires | Writable Fields |
|-------|--------------|-----------------|
| `AgentInitializedEvent` | After agent construction | None |
| `BeforeInvocationEvent` | Start of agent call | `messages`, `invocation_state` |
| `AfterInvocationEvent` | End of agent call (reversed order) | None |
| `BeforeModelCallEvent` | Before LLM inference | `invocation_state` |
| `AfterModelCallEvent` | After LLM inference (reversed order) | `retry` |
| `BeforeToolCallEvent` | Before tool execution | `cancel_tool`, `selected_tool`, `tool_use`, `invocation_state` |
| `AfterToolCallEvent` | After tool execution (reversed order) | `result`, `retry`, `exception`, `cancel_message` |
| `MessageAddedEvent` | When message added to history | `message` |

### Multi-Agent Events

| Event | When it Fires |
|-------|--------------|
| `MultiAgentInitializedEvent` | Orchestrator initializes |
| `BeforeMultiAgentInvocationEvent` | Before orchestrator execution |
| `AfterMultiAgentInvocationEvent` | After orchestrator execution (reversed) |
| `BeforeNodeCallEvent` | Before a node executes (can cancel via `cancel_node`) |
| `AfterNodeCallEvent` | After a node executes (reversed) |

### Registering Hooks - Method 1: HookProvider Class

```python
from strands import Agent
from strands.hooks.registry import HookProvider, HookRegistry
from strands.hooks.events import (
    BeforeToolCallEvent,
    AfterToolCallEvent,
    BeforeModelCallEvent,
)

class LoggingHooks(HookProvider):
    def register_hooks(self, registry: HookRegistry, **kwargs):
        registry.add_callback(BeforeModelCallEvent, self.on_before_model)
        registry.add_callback(BeforeToolCallEvent, self.on_before_tool)
        registry.add_callback(AfterToolCallEvent, self.on_after_tool)

    def on_before_model(self, event: BeforeModelCallEvent):
        print("Model inference starting...")

    def on_before_tool(self, event: BeforeToolCallEvent):
        print(f"Calling tool: {event.tool_use['name']}")
        # Cancel a tool call:
        # event.cancel_tool = "Tool call cancelled for safety"

    def on_after_tool(self, event: AfterToolCallEvent):
        print(f"Tool {event.tool_use['name']} completed: {event.result['status']}")
        # Retry on error:
        # if event.exception:
        #     event.retry = True

agent = Agent(tools=[my_tool], hooks=[LoggingHooks()])
```

### Registering Hooks - Method 2: Inline with add_hook()

```python
agent = Agent(tools=[my_tool])

def on_tool_call(event: BeforeToolCallEvent):
    print(f"Tool: {event.tool_use['name']}")

# Type is auto-inferred from the function signature
agent.add_hook(on_tool_call)

# Or register on the hook registry directly
agent.hooks.add_callback(BeforeToolCallEvent, on_tool_call)
```

### Hook Ordering

- `Before*` events: Callbacks fire in registration order (FIFO)
- `After*` events: Callbacks fire in **reverse** order (LIFO) - enabling proper cleanup/unwinding

---

## 12. Plugin System

Plugins provide a structured way to extend agent behavior:

```python
from strands import Plugin, Agent
from strands.hooks.events import BeforeModelCallEvent, AfterToolCallEvent

class SecurityAuditPlugin(Plugin):
    name = "security_audit"

    def init_plugin(self, agent: Agent) -> None:
        """Called when plugin is registered with an agent."""
        self.audit_log = []
        agent.add_hook(self.log_model_call)
        agent.add_hook(self.log_tool_call)

    def log_model_call(self, event: BeforeModelCallEvent):
        self.audit_log.append({"type": "model_call", "timestamp": time.time()})

    def log_tool_call(self, event: AfterToolCallEvent):
        self.audit_log.append({
            "type": "tool_call",
            "tool": event.tool_use["name"],
            "status": event.result.get("status"),
            "timestamp": time.time(),
        })

plugin = SecurityAuditPlugin()
agent = Agent(plugins=[plugin])
agent("Do something")
print(plugin.audit_log)  # Access audit data
```

---

## 13. Observability and Tracing (OpenTelemetry)

Strands has **built-in OpenTelemetry integration** via the telemetry module.

### Configuration via Environment Variables

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_SEMCONV_STABILITY_OPT_IN="gen_ai_latest_experimental"
```

### Span Types Created Automatically

1. **Agent spans** (`start_agent_span`) - Track full agent invocations with tools and responses
2. **Model invocation spans** (`start_model_invoke_span`) - Trace LLM calls with messages, model ID, token usage
3. **Tool call spans** (`start_tool_call_span`) - Capture tool execution with input/output
4. **Event loop cycle spans** (`start_event_loop_cycle_span`) - Monitor processing iterations
5. **Multi-agent/swarm spans** (`start_multiagent_span`) - Track multi-agent coordination

### Span Attributes (GenAI Semantic Conventions)

- `gen_ai.operation.name` - Operation type
- `gen_ai.provider.name` / `gen_ai.system` - Provider identification
- `gen_ai.usage.prompt_tokens` / `gen_ai.usage.output_tokens` - Token usage
- `gen_ai.server.time_to_first_token` - Latency metrics
- `gen_ai.server.request.duration` - Request duration
- `gen_ai.event.start_time` / `gen_ai.event.end_time` - Timestamps

### Custom Trace Attributes

```python
agent = Agent(
    trace_attributes={
        "app.environment": "production",
        "app.version": "1.0.0",
        "app.agent_type": "red_team",
    }
)
```

### Programmatic Access

```python
from strands.telemetry.tracer import get_tracer

tracer = get_tracer()  # Singleton instance
# Tracer wraps OpenTelemetry's TracerProvider
# Supports thread instrumentation
# Non-critical telemetry failures don't crash the agent
```

### Telemetry Module Structure

```
strands/telemetry/
├── __init__.py
├── config.py              # Configuration settings
├── metrics.py             # Metrics collection and emission
├── metrics_constants.py   # Predefined metric identifiers
└── tracer.py              # OpenTelemetry distributed tracing
```

---

## 14. Structured Output

Force the agent to return data matching a Pydantic model:

```python
from pydantic import BaseModel
from strands import Agent

class SecurityFinding(BaseModel):
    vulnerability: str
    severity: str          # "low", "medium", "high", "critical"
    description: str
    recommendation: str
    cvss_score: float

agent = Agent()
result = agent(
    "Analyze: SQL injection found in login form parameter 'username'",
    structured_output_model=SecurityFinding,
)
finding = result.structured_output
print(finding.vulnerability)    # "SQL Injection"
print(finding.severity)         # "critical"
print(finding.cvss_score)       # 9.8
```

---

## 15. Community Tools (strands-agents-tools)

The `strands-agents-tools` package provides 50+ pre-built tools:

### Key Categories

**File & System**: `file_read`, `file_write`, `editor`, `shell`, `environment`
**Web & API**: `http_request`, `tavily_search`, `tavily_extract`, `tavily_crawl`, `exa_search`, `bright_data`
**Code Execution**: `python_repl`, `code_interpreter`, `calculator`
**Memory & Knowledge**: `mem0_memory`, `agent_core_memory`, `memory` (Bedrock KB), `mongodb_memory`, `elasticsearch_memory`, `retrieve`
**AWS**: `use_aws`
**Agent Coordination**: `swarm`, `agent_graph`, `a2a_client`, `handoff_to_user`
**Media**: `generate_image`, `generate_image_stability`, `image_reader`, `speak`, `nova_reels`
**Automation**: `browser`, `use_computer`, `cron`, `workflow`, `batch`
**Utility**: `current_time`, `think`, `stop`, `sleep`, `load_tool`, `use_llm`, `journal`, `diagram`
**Communication**: `slack`, `rss`

```python
from strands_tools import (
    http_request, calculator, python_repl, shell,
    file_read, file_write, current_time, think,
)
```

---

## 16. Complete Working Examples

### Example 1: Agent with Custom Tools and State

```python
import json
from strands import Agent, tool, ToolContext
from strands.models.bedrock import BedrockModel
from strands.session.file_session_manager import FileSessionManager
from strands.handlers.callback_handler import PrintingCallbackHandler
from strands.hooks.events import BeforeToolCallEvent, AfterInvocationEvent

# --- Model ---
model = BedrockModel(
    model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
    region_name="us-east-1",
    max_tokens=4096,
    temperature=0.3,
)

# --- Custom Tools ---
@tool(context=True)
def analyze_vulnerability(
    target: str,
    attack_type: str,
    severity: str = "medium",
    tool_context: ToolContext = None,
) -> dict:
    """Analyze a potential security vulnerability in the target system.

    Args:
        target: The system component or endpoint to analyze.
        attack_type: Type of attack (sql_injection, xss, prompt_injection, etc.).
        severity: Expected severity level (low, medium, high, critical).
    """
    findings = tool_context.agent.state.get("findings", [])
    finding = {
        "target": target,
        "attack_type": attack_type,
        "severity": severity,
        "status": "analyzed",
    }
    findings.append(finding)
    tool_context.agent.state["findings"] = findings

    return {
        "status": "success",
        "content": [{"text": json.dumps(finding)}],
    }

@tool
def generate_report(format: str = "markdown") -> str:
    """Generate a security assessment report from all findings.

    Args:
        format: Output format (markdown, json, html).
    """
    return f"# Security Assessment Report\n\nFormat: {format}\n..."

# --- Hooks ---
def log_tool_calls(event: BeforeToolCallEvent):
    print(f"\n[HOOK] Tool: {event.tool_use['name']} input: {event.tool_use.get('input', {})}")

def on_complete(event: AfterInvocationEvent):
    if event.result:
        print(f"\n[HOOK] Completed: stop_reason={event.result.stop_reason}")

# --- Session ---
session_mgr = FileSessionManager(session_id="red-team-001", storage_dir="/tmp/strands/sessions")

# --- Agent ---
agent = Agent(
    name="CrimsonAgent",
    model=model,
    system_prompt="""You are Crimson, an expert AI red-teaming agent. Your mission is to:
1. Analyze target systems for security vulnerabilities
2. Simulate attack scenarios
3. Generate comprehensive security assessment reports
Always be thorough and document all findings.""",
    tools=[analyze_vulnerability, generate_report],
    callback_handler=PrintingCallbackHandler(verbose_tool_use=True),
    session_manager=session_mgr,
    agent_id="crimson-001",
    state={"findings": [], "session_type": "red_team"},
    trace_attributes={"app.agent_type": "red_team"},
)

agent.add_hook(log_tool_calls)
agent.add_hook(on_complete)

# --- Run ---
result = agent("Analyze the login endpoint for SQL injection and XSS vulnerabilities")
print(f"\nFindings: {agent.state.get('findings', [])}")
```

### Example 2: Multi-Agent Red Team Swarm

```python
from strands import Agent, tool
from strands.models.bedrock import BedrockModel
from strands.multiagent import Swarm

model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-20250514-v1:0", region_name="us-east-1")

scanner = Agent(
    name="scanner",
    description="Identifies attack surfaces and potential vulnerabilities",
    model=model,
    system_prompt="You are a vulnerability scanner. Identify potential attack surfaces.",
    tools=[scan_tool],
)

attacker = Agent(
    name="attacker",
    description="Attempts to exploit identified vulnerabilities",
    model=model,
    system_prompt="You are a penetration tester. Attempt to exploit vulnerabilities.",
    tools=[exploit_tool],
)

reporter = Agent(
    name="reporter",
    description="Compiles findings into actionable security reports",
    model=model,
    system_prompt="You compile findings into security reports.",
    tools=[report_tool],
)

swarm = Swarm(
    nodes=[scanner, attacker, reporter],
    entry_point=scanner,
    max_handoffs=15,
    max_iterations=20,
    execution_timeout=600,
)

result = swarm("Perform a security assessment of the payment processing system")
```

### Example 3: Graph-Based Assessment Pipeline

```python
from strands import Agent
from strands.multiagent import GraphBuilder

planner = Agent(name="planner", system_prompt="Break the assessment into phases.")
researcher = Agent(name="researcher", system_prompt="Research attack vectors.", tools=[search])
analyst = Agent(name="analyst", system_prompt="Analyze vulnerabilities.", tools=[analyze])
writer = Agent(name="writer", system_prompt="Write the final assessment report.")

builder = GraphBuilder()
builder.add_node(planner, "plan")
builder.add_node(researcher, "research")
builder.add_node(analyst, "analyze")
builder.add_node(writer, "write")

builder.add_edge("plan", "research")
builder.add_edge("plan", "analyze")      # Parallel: research + analyze
builder.add_edge("research", "write")
builder.add_edge("analyze", "write")     # write waits for both

builder.set_entry_point("plan")
builder.set_execution_timeout(600.0)

graph = builder.build()
result = await graph.invoke_async("Build a comprehensive security assessment")
```

---

## 17. Key Types Reference

```python
# Core imports
from strands import Agent, AgentBase, tool, ToolContext, Plugin, ModelRetryStrategy

# Models
from strands.models.bedrock import BedrockModel
from strands.models.anthropic import AnthropicModel
from strands.models.openai import OpenAIModel
from strands.models.ollama import OllamaModel
from strands.models.litellm import LiteLLMModel

# Multi-agent
from strands.multiagent import Swarm, GraphBuilder, MultiAgentBase, MultiAgentResult, Status

# Tools
from strands.tools.mcp import MCPClient
from strands.tools.registry import ToolRegistry
from strands.types.tools import ToolSpec, ToolUse, ToolResult, AgentTool

# Conversation management
from strands.agent.conversation_manager import SlidingWindowConversationManager

# Hooks
from strands.hooks.registry import HookProvider, HookRegistry
from strands.hooks.events import (
    AgentInitializedEvent,
    BeforeInvocationEvent, AfterInvocationEvent,
    BeforeModelCallEvent, AfterModelCallEvent,
    BeforeToolCallEvent, AfterToolCallEvent,
    MessageAddedEvent,
    MultiAgentInitializedEvent,
    BeforeMultiAgentInvocationEvent, AfterMultiAgentInvocationEvent,
    BeforeNodeCallEvent, AfterNodeCallEvent,
)

# Session
from strands.session.file_session_manager import FileSessionManager
from strands.session.s3_session_manager import S3SessionManager

# Handlers
from strands.handlers.callback_handler import (
    PrintingCallbackHandler, CompositeCallbackHandler, null_callback_handler
)

# Telemetry
from strands.telemetry.tracer import get_tracer
```

---

## 18. Architecture Summary

```
strands/
├── agent/                    # Core Agent class and conversation management
│   ├── agent.py              # Agent class (main orchestrator)
│   ├── base.py               # AgentBase abstract class
│   └── conversation_manager/ # Context window management
├── event_loop/               # The agent reasoning/tool-calling loop
│   ├── event_loop.py         # event_loop_cycle() - the core execution engine
│   ├── streaming.py          # Streaming event processing
│   └── _retry.py             # ModelRetryStrategy
├── models/                   # Model provider implementations (12+)
│   ├── bedrock.py, anthropic.py, openai.py, ollama.py, gemini.py, ...
│   └── model.py              # Base model interface
├── multiagent/               # Multi-agent orchestration
│   ├── base.py               # MultiAgentBase, Status, NodeResult, MultiAgentResult
│   ├── swarm.py              # Swarm (autonomous handoffs, shared context)
│   ├── graph.py              # Graph (DAG execution, parallel, conditional)
│   └── a2a/                  # Agent-to-Agent protocol
├── tools/                    # Tool system
│   ├── decorator.py          # @tool decorator (FunctionToolMetadata, DecoratedFunctionTool)
│   ├── registry.py           # ToolRegistry (discovery, validation, hot-reload)
│   └── mcp/                  # MCP client integration
├── hooks/                    # Lifecycle hook system
│   ├── registry.py           # HookRegistry, HookProvider
│   └── events.py             # All event types (Agent, Tool, Model, MultiAgent)
├── plugins/                  # Plugin framework
├── session/                  # Session persistence (File, S3, Repository)
├── telemetry/                # OpenTelemetry integration (traces, metrics)
├── handlers/                 # Callback handlers (Printing, Composite, null)
├── types/                    # Type definitions (ToolContext, ToolSpec, AgentTool, etc.)
├── experimental/             # Experimental features (bidirectional streaming)
└── __init__.py               # Public API: Agent, tool, ToolContext, Plugin, etc.
```

---

## 19. Key Design Patterns

1. **Model-Driven**: The LLM decides tool selection and orchestration, not hardcoded logic
2. **Decorator Pattern**: `@tool` converts plain Python functions into agent tools
3. **Provider Pattern**: Model providers implement a common interface, enabling hot-swapping
4. **Registry Pattern**: ToolRegistry manages discovery, validation, and lifecycle of tools
5. **Observer Pattern**: Hook system allows non-invasive lifecycle observation and modification
6. **Builder Pattern**: GraphBuilder provides fluent API for constructing execution graphs
7. **Context Manager**: MCPClient uses `with` statements for clean resource management
8. **Composability**: MultiAgentBase allows nesting (Graph containing Swarms, etc.)
9. **Hook-Based Persistence**: SessionManager uses hooks to auto-persist state on lifecycle events
10. **Dual Invocation**: Tools work both as regular Python functions AND as agent tool calls
