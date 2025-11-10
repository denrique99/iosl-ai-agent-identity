import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, AsyncIterable, List

import httpx
import nest_asyncio
from a2a.client import A2ACardResolver
from a2a.types import (
    AgentCard,
    Message,
    MessageSendParams,
    SendMessageRequest,
    SendMessageResponse,
    SendMessageSuccessResponse,
    Task,
    Part,
    Role,
    TextPart,
    DataPart,
)
from dotenv import load_dotenv

from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from domain_b.main import get_agent_b
from google_a2a.remote_agent_connection import RemoteAgentConnections
import os

load_dotenv()
nest_asyncio.apply()
api_key = os.getenv("OPENAI_API_KEY")
host_instance = None
logger = logging.getLogger(__name__)

class HostAgent:
    """The Host agent."""

    def __init__(
        self,
    ):
        self.remote_agent_connections: dict[str, RemoteAgentConnections] = {}
        self.cards: dict[str, AgentCard] = {}
        self.agents: str = ""
        self._agent: AssistantAgent | None = None
        self._user_id = "host_agent"
        self._sessions: dict[str, tuple[str, str]] = {}

    async def _async_init_components(self, remote_agent_addresses: List[str]):
        async with httpx.AsyncClient(timeout=45.0) as client:
            for address in remote_agent_addresses:
                card_resolver = A2ACardResolver(client, address)
                try:
                    card = await card_resolver.get_agent_card()
                    remote_connection = RemoteAgentConnections(agent_card=card,agent_url=address)
                    self.remote_agent_connections[card.name] = remote_connection
                    self.cards[card.name] = card
                except httpx.ConnectError as e:
                    print(f"ERROR: Failed to get agent card from {address}: {e}")
                except Exception as e:
                    print(f"ERROR: Failed to initialize connection for {address}: {e}")

        agent_info = [
            json.dumps({"name": card.name, "description": card.description})
            for card in self.cards.values()
        ]
        print("agent_info:", agent_info)
        self.agents = "\n".join(agent_info) if agent_info else "No friends found"

    @classmethod
    async def create(
        cls,
        remote_agent_addresses: List[str],
    ):
        instance = cls()
        agent_b = await get_agent_b()
        instance._agent = agent_b
        await instance._async_init_components(remote_agent_addresses)
        return instance

    async def send_message_to_server(self, agent_name: str, prompt: str | None = None,
                           data: dict | list | None = None):
        """Sends a task to a remote friend agent."""
        if agent_name not in self.remote_agent_connections:
            raise ValueError(f"Agent {agent_name} not found")
        client = self.remote_agent_connections[agent_name]

        if not client:
            raise ValueError(f"Client not available for {agent_name}")
        task_id, ctx_id = self._sessions.get(agent_name, (None, None))

        input_parts: list[Part] = []
        if prompt:
            input_parts.append(Part(root=TextPart(text=prompt)))

        if data is not None:            # dict, list, vb.
            input_parts.append(
                Part(root=DataPart(mime_type="application/json", data=data))
            )
        message_payload = Message(
            role=Role.user,
            taskId=task_id,
            contextId=ctx_id,
            messageId=str(uuid.uuid4()),
            parts=input_parts,
        )
        message_request = SendMessageRequest(
            id=str(uuid.uuid4()), params=MessageSendParams(
                message=message_payload,
        ))
        send_response: SendMessageResponse = await client.send_message(message_request)
        logger.info("send_response: %s", send_response)
        result: Task = send_response.root.result
        self._sessions[agent_name] = (result.id, result.contextId)

        if not isinstance(
            send_response.root, SendMessageSuccessResponse
        ) or not isinstance(send_response.root.result, Task):
            print("Received a non-success or non-task response. Cannot proceed.")
            return

        resp = {"text": [], "data": []}
        if result.artifacts:
            for artifact in result.artifacts:
                for part in artifact.parts:
                    if isinstance(part.root, TextPart):
                        resp["text"].append(part.root.text)
                    elif isinstance(part.root, DataPart):
                        try:
                            resp["data"].append({"purpose": part.root.metadata.get("purpose", "No purpose"), 
                                           "data": part.root.data})
                        except json.JSONDecodeError:
                            print(f"Failed to decode JSON from DataPart: {part.root.data}")
                       
        return resp


def _get_initialized_host_agent_sync():
    """Synchronously creates and initializes the HostAgent."""

    async def _async_main():
        # Hardcoded URLs for the friend agents
        friend_agent_urls = [
            "http://localhost:10004",  #Agent A
        ]

        print("initializing host agent")
        hosting_agent_instance = await HostAgent.create(
            remote_agent_addresses=friend_agent_urls
        )
        print("HostAgent initialized")
        return hosting_agent_instance

    try:
        host_instance = asyncio.run(_async_main())
    except RuntimeError as e:
        if "asyncio.run() cannot be called from a running event loop" in str(e):
            print(
                f"Warning: Could not initialize HostAgent with asyncio.run(): {e}. "
                "This can happen if an event loop is already running (e.g., in Jupyter). "
                "Consider initializing HostAgent within an async function in your application."
            )
            host_instance = asyncio.get_event_loop().run_until_complete(_async_main())
        else:
            raise
    return host_instance


host_instance = _get_initialized_host_agent_sync()