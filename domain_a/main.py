import uuid
import datetime
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.prebuilt import create_react_agent
from langgraph_swarm import create_handoff_tool, create_swarm
from langchain.memory import ConversationBufferMemory
from dotenv import load_dotenv
# Load environment variables
load_dotenv()

# Import tools and prompts from the respective modules
from domain_a.agent_x.tools_x import (create_presentation_definition,check_signature_vp,check_signature_vc,vc_matches_pd,create_vp, issue_credential, create_credential_manifest)
TOOLS_X = [create_presentation_definition,check_signature_vp,check_signature_vc,create_vp,vc_matches_pd, issue_credential, create_credential_manifest]

from domain_a.agent_a.tools_a import (vc_matches_pd,create_vp,create_presentation_definition,
                                      check_signature_vp,check_signature_vc,create_credential_application,
                                        save_credential,vc_airport_matches_pd,create_vp_for_agentb,
                                        create_presentation_definition_b)
TOOLS_A = [create_presentation_definition,check_signature_vp,check_signature_vc,
           create_vp,vc_matches_pd, save_credential,create_credential_application,
           vc_airport_matches_pd,create_vp_for_agentb,create_presentation_definition_b]
#Import prompts for agents
from domain_a.agent_x.agent_x_prompt import AGENT_X_PROMPT
from domain_a.agent_a.agent_a_prompt import AGENT_A_PROMPT

def make_prompt(base: str):
    """
    Creates a prompt function that includes the base prompt and the current date.
    Args:
        base (str): The base prompt text to be used in the system message.
    Returns: 
        function: A function that takes the state and config, and returns a list of messages including the base prompt and the current date.
    """
    def _prompt(state: dict, config) -> list:
        today = datetime.datetime.now()
        return [
            {"role": "system", "content": f"{base}\n\nToday is: {today}"},
            *state["messages"],
        ]
    return _prompt
checkpointer = InMemorySaver()

model = ChatOpenAI(model="gpt-4o-mini", temperature=0)

# Handoff tools for transferring between agents
transfer_to_agent_a = create_handoff_tool(
    agent_name="agent_a",
    description=" Transfer to agent_a (Agent A) for other tasks."
)
transfer_to_agent_x = create_handoff_tool(
    agent_name="agent_x",
    description=" Transfer to agent_x (Agent X) for other tasks."
)

agent_x_tools = TOOLS_X + [transfer_to_agent_a] 
# Agent X
agent_x = create_react_agent(
    model,
    tools=agent_x_tools,
    prompt=make_prompt(AGENT_X_PROMPT),
    name="agent_x",
)

agent_a_tools = TOOLS_A + [transfer_to_agent_x] 
# Agent A
agent_a = create_react_agent(
    model,
    tools=agent_a_tools,
    prompt=make_prompt(AGENT_A_PROMPT),
    name="agent_a",
    checkpointer=checkpointer,
)

# Create the swarm with both agents
builder = create_swarm(
    [agent_x, agent_a],
    default_active_agent="agent_a", 
)
app = builder.compile(checkpointer=checkpointer)

# Pretty print function for the stream output
def print_stream(stream):
    for ns, update in stream:
        print(f"Namespace '{ns}'")
        for node, node_updates in update.items():
            if node_updates is None:
                continue

            if isinstance(node_updates, (dict, tuple)):
                node_updates_list = [node_updates]
            elif isinstance(node_updates, list):
                node_updates_list = node_updates
            else:
                raise ValueError(node_updates)

            for node_updates in node_updates_list:
                print(f"Update from node '{node}'")
                if isinstance(node_updates, tuple):
                    print(node_updates)
                    continue
                messages_key = next(
                    (k for k in node_updates.keys() if "messages" in k), None
                )
                if messages_key is not None:
                    node_updates[messages_key][-1].pretty_print()
                else:
                    print(node_updates)

        print("\n\n")
    print("\n===\n")


if __name__ == "__main__":
    print("\n--- SWARM STARTED ---\n")
    config = {"configurable": {"thread_id": str(uuid.uuid4()), "user_id": "1"}}
    stream = app.stream(
        {
            "messages": [
                {"role": "user", "content": "Hi Agent A, you may start your procedure!"}
            ]
        },
        config,
        subgraphs=True,
    )
    print_stream(stream)