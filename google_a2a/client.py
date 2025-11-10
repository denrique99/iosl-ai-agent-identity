import asyncio
import json
from google_a2a.host_agent import host_instance
from autogen_agentchat.conditions import FunctionCallTermination ,TextMentionTermination
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.messages import ToolCallExecutionEvent
from autogen_core.models._types import FunctionExecutionResult


def format_agent_response(text_json):
    parts = []

    if "text" in text_json:
        text_array = text_json["text"]
        parts.append("Text Messages from Agent A:")
        for text in text_array:
            parts.append(text)
    if "data" in text_json:
        data_array = text_json["data"]
        for data in data_array:
            # add purpose
            purpose =data["purpose"] if "purpose" in data else "No purpose"
            parts.append(f"Purpose: {purpose}")
            # add data
            data = data["data"] if "data" in data else {}
            parts.append("Data:")
            # it is a dictionary ,give as json quoted string
            if isinstance(data, dict):
                parts.append("```json\n" + json.dumps(data) + "\n```")
    return "\n\n".join(parts)

async def main() -> None:
    root_agent = host_instance._agent
    print("Root agent created successfully.")
    print("Root agent name:", root_agent.name)
    msg = " You are in PHASE 4 and communicating with Agent A. Your first step and others written in PHASE 4 "
    termination_condition = FunctionCallTermination("send_message_to_host_tool") | TextMentionTermination("goodbye")
    team = RoundRobinGroupChat(
    [root_agent],
    termination_condition=termination_condition,
    )
    for _ in range(8):     
        print("--" * 20)
        print("Sending following message to host agent:")
        print(msg)
        print("--" * 20)   
        resp = await team.run(task=msg)
        print("Response from host agent:")
        print(resp)
        print("--" * 20)
        response_from_a =""
        for resp_msg in resp.messages:
            if isinstance(resp_msg,ToolCallExecutionEvent):
                content_array:list[FunctionExecutionResult] = resp_msg.content
                for item in content_array:
                    if isinstance(item, FunctionExecutionResult) and item.name == "send_message_to_host_tool":
                        raw_json=item.content
                        content_list = json.loads(raw_json)
                        for element in content_list:
                            text_Str = element.get("text", "")
                            text_json =json.loads(text_Str) if isinstance(text_Str, str) else text_Str
                            response_from_a += format_agent_response(text_json) + "\n\n"
        if 'goodbye' in response_from_a.lower():
            print("Agent A has said goodbye. Ending conversation.")
            break
        print("Agent A has responded with the following message:", response_from_a)
        msg = "Agent A has responded with the following message: " + response_from_a 
if __name__ == "__main__":
    asyncio.run(main())