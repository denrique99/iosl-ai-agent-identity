import json
import logging

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import (
    InternalError,
    Part,
    TextPart,
    DataPart,
    UnsupportedOperationError,
)
from a2a.utils.errors import ServerError
from domain_a.main import agent_a
logger = logging.getLogger(__name__)
from langchain.schema.messages import ToolMessage,AIMessage


class Agent_a_Executor(AgentExecutor):
    """Executor für Agent A, erstellt mit create_react_agent (LangGraph)."""

    def __init__(self):
        self.agent = agent_a

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        if not context.task_id or not context.context_id:
            raise ValueError("RequestContext must have task_id and context_id")
        if not context.message:
            raise ValueError("RequestContext must have a message")

        updater = TaskUpdater(event_queue, context.task_id, context.context_id)

        try:
            # Neues Task-Update, falls nicht vorhanden
            if not context.current_task:
                await updater.submit()
            await updater.start_work()

            user_prompt = None
            data = None
            print("CONTEXT MESSAGE:")
            print(context.message)
            print("------")
            for part in context.message.parts:
                root = part.root
                if isinstance(root, TextPart):
                    user_prompt = root.text.strip()
                    print(f"User prompt: {user_prompt}")
                    print("------")
                elif isinstance(root, DataPart):
                    data = root.data  
                    print(f"Data part: {data}")
                    print("------")
            messages =[]
            messages.append({
                "role": "user",
                "content": user_prompt
            })
            if data is not None:
                json_str = json.dumps(data)
                messages.append({
                    "role": "user",
                    "content": f"Here is JSON data comes from the Agent B:\n ```json {json_str} ```"
                })
            logger.info("[Agent A] Received messages: %s", messages)
            config = {"configurable": {"thread_id": context.context_id, "user_id": "a2a_user"}}
            result = await self.agent.ainvoke({"messages": messages}, config=config)
            # Agent A LangGraph invoke
            print("------")
            print("Agent A invoke result:")
            print(result)
            print("------")
            messages = result["messages"]
            
            tool_parts = []
            for msg in messages:
                if isinstance(msg, ToolMessage) and msg.name =='create_vp_for_agentb':
                    content = msg.content
                    print("------")
                    print(f"Tool message VP content: {content}")
                    part = Part(
                        root=DataPart(
                            mime_type="application/json",
                            data=json.loads(content) if isinstance(content, str) else content,
                            metadata={"purpose": "Verifiable Presentation for Agent B"}                   
                        )
                    )
                    tool_parts.append(part)
                elif isinstance(msg, ToolMessage) and msg.name == 'create_presentation_definition_b':
                    content = msg.content
                    print("------")
                    print(f"Tool message PD content: {content}")
                    part = Part(
                        root=DataPart(
                            mime_type="application/json",
                            data=json.loads(content) if isinstance(content, str) else content,
                            metadata={"purpose": "Presentation Definition for Agent B"}
                        )
                    )
                    tool_parts.append(part)
            if tool_parts:
                logger.info(f"[Agent A] Sending tool parts: {tool_parts}")
                await updater.add_artifact(parts=tool_parts, name="agent_a_tools")
            
            part_array= []
            part = Part(root=TextPart(text="Hey Agent B, Here is the result of my work."))
            part_array.append(part)
            last_message = messages[-1] if messages else None
            if last_message and isinstance(last_message,AIMessage):
                text = last_message.content.strip()
                if text:
                    part = Part(root=TextPart(text=text))
                    part_array.append(part)
            await updater.add_artifact(parts=part_array, name="agent_a_result")
            await updater.complete()

        except Exception as e:
            logger.exception("Error during Agent A execution: %s", e)
            raise ServerError(error=InternalError(message=str(e))) from e

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise ServerError(error=UnsupportedOperationError())
