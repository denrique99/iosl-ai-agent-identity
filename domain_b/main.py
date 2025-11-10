import asyncio
import os
from dotenv import load_dotenv
from pathlib import Path
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.conditions import TextMentionTermination
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.ui import Console
import datetime

#Import prompts for agents
from domain_b.agents.agent_b.agent_b_prompt import AGENT_B_PROMPT
from domain_b.agents.agent_y.agent_y_prompt import AGENT_Y_PROMPT

def make_prompt(base: str) -> str:
    """
    Creates a system prompt string that includes the base prompt and the current date.
    
    Args:
        base (str): The base prompt text to be used in the system message.
    
    Returns:
        str: A single string containing the base prompt followed by the current date.
    """
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    return f"{base}\n\nToday is: {today}"

# Load environment variables from .env file
load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

async def get_agent_b():
    mcp_path_holder = Path(__file__).parent.parent / "mcp_server_setup" / "mcp_holder_tools" / "mcp_server_holder_tools.py"

    fetch_mcp_server_holder = StdioServerParams(
        command="python",
        args=[str(mcp_path_holder)],
        read_timeout_seconds=45
    )

    holder_tools = await mcp_server_tools(fetch_mcp_server_holder)

    model_client = OpenAIChatCompletionClient(
        model="gpt-4.1-mini",
        api_key=api_key,
        temperature=0.0
    )

    return AssistantAgent(
        name="agent_b",
        model_client=model_client,
        tools=holder_tools,
        reflect_on_tool_use=True,
        system_message=make_prompt(AGENT_B_PROMPT)
    )

async def main() -> None:
    # dynamic path of mcp_holder_tools.py
    # mcp_path = Path(__file__).parent.parent / "mcp_server_setup" / "mcp_server_tools.py"

    # all_tools = await mcp_server_tools(fetch_mcp_server)

    # subset the tools for the holder agent

    # dynamic path of mcp_issuer_tools.py
    mcp_path_issuer = Path(__file__).parent.parent / "mcp_server_setup" / "mcp_issuer_tools" / "mcp_server_issuer_tools.py"

    fetch_mcp_server_issuer = StdioServerParams(
        command="python", 
        args=[str(mcp_path_issuer)], 
        read_timeout_seconds=45
    )

    issuer_tools = await mcp_server_tools(fetch_mcp_server_issuer)

    # Create an agent that can use the fetch tool.
    model_client = OpenAIChatCompletionClient(
        model="gpt-4.1-mini",
        api_key=api_key,
        temperature=0.0
    )

# issuer agent
    agent_y = AssistantAgent(
        name="agent_y", 
        model_client=model_client, 
        tools=issuer_tools, 
        reflect_on_tool_use=True,
        system_message=make_prompt(AGENT_Y_PROMPT)
    )   

# holder agent
    agent_b = await get_agent_b()
    
    # Define a termination condition that stops the task if the critic approves.
    text_termination = TextMentionTermination("Goodbye")

    # Create a team with the agents and the termination condition.
    team = RoundRobinGroupChat(
        # [agent_y, agent_b], 
        [agent_b, agent_y],
        termination_condition=text_termination
        )

    await team.reset()  # Reset the team for a new task.
    await Console(team.run_stream(task="The holder agent (Agent B) wants the issuer agent (Agent Y) to issue it a verifiable credential."))
 
if __name__ == "__main__":
    asyncio.run(main())

