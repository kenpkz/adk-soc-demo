# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.adk.agents import Agent
from google.adk.tools.agent_tool import AgentTool
from .prompts import agent_instruction
from .sub_agents.detection_agent.agent import root_agent as detection_agent
from .sub_agents.analysis_agent.agent import root_agent as analysis_agent
from .sub_agents.response_agent.agent import root_agent as response_agent
from .sub_agents.forensics_agent.agent import root_agent as forensics_agent
from .sub_agents.reporting_agent.agent import root_agent as reporting_agent

root_agent = Agent(
    model="gemini-2.5-flash",
    name="ir_bot",
    instruction=agent_instruction,
    tools=[
        AgentTool(agent=detection_agent),
        AgentTool(agent=analysis_agent),
        AgentTool(agent=response_agent),
        AgentTool(agent=forensics_agent),
        AgentTool(agent=reporting_agent),
    ],
)
