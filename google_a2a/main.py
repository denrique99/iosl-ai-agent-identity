import logging
import os
import sys

import httpx
import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryPushNotifier, InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from google_a2a.agent_a_executer import Agent_a_Executor
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MissingAPIKeyError(Exception):
    """Exception for missing API key."""


def main():
    """Starts Agent A's server."""
    host = "localhost"
    port = 10004
    try:
        if not os.getenv("OPENAI_API_KEY"):
            raise MissingAPIKeyError("OPENAI_API_KEY environment variable not set.")

        capabilities = AgentCapabilities(streaming=True, pushNotifications=True)
        skill = AgentSkill(
            id="Authenticate and Verify Credentials",
            name="Authentication and Verification",
            description="Helps with authenticating and verifying credentials.",
            tags=["authentication", "verification"],
            examples=["Is this agent authorized?", "Verify the agent's identity."],
        )
        agent_card = AgentCard(
            name="agent_a",
            description="Agent A is a specialized agent to authenticate and verify credentials of other agents.",
            url=f"http://{host}:{port}/",
            version="1.0.0",
            # defaultInputModes=agent_a.SUPPORTED_CONTENT_TYPES,
            # defaultOutputModes=agent_a.SUPPORTED_CONTENT_TYPES,
            defaultInputModes=["text/plain"],
            defaultOutputModes=["text/plain"],
            capabilities=capabilities,
            skills=[skill],
        )

        httpx_client = httpx.AsyncClient(timeout=httpx.Timeout(45.0))  
        request_handler = DefaultRequestHandler(
            agent_executor=Agent_a_Executor(),
            task_store=InMemoryTaskStore(),
            push_notifier=InMemoryPushNotifier(httpx_client),
        )
        server = A2AStarletteApplication(
            agent_card=agent_card, http_handler=request_handler
        )

        uvicorn.run(server.build(), host=host, port=port)

    except MissingAPIKeyError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred during server startup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# python -m domain_a_swarm.a2a_agent_a.main to start server
# http://localhost:10004/.well-known/agent.json to check agent card