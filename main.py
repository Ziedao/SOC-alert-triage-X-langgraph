import os
from dotenv import load_dotenv
from typing import TypedDict, Annotated, List, Literal

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode

# Import the tools directly from your tools.py file
from tools import get_virustotal_report, check_abuseipdb, get_geoip_location, check_vpn_proxy


# Load environment variables
load_dotenv()
# Set the Google API key from the environment variable
os.environ["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY")

# Define the graph state
class GraphState(TypedDict):
    initial_alert: str
    plan: str
    tool_results: List[str]
    final_analysis: str
    messages: Annotated[List[BaseMessage], lambda x, y: x + y]

# Initialize LLM and bind tools
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
# We bind the tools here, so the LLM knows what functions it can call.
llm_with_tools = llm.bind_tools([get_virustotal_report, check_abuseipdb, get_geoip_location, check_vpn_proxy])


# --- Agent and Router Functions ---

# Triage Agent
def triage_agent(state: GraphState):
    print("---TRIAGE AGENT: Analyzing alert and creating a plan---")
    initial_alert = state['initial_alert']
    prompt = f"""
    You are a highly skilled SOC analyst. Your task is to analyze a security alert and develop a comprehensive investigation plan.
    Based on the following alert, create a step-by-step plan to investigate it.
    
    Alert: {initial_alert}
    
    
    
    Your final output should be a detailed, actionable investigation plan. with tools cals needed.
    i want all the tool calls to be at the end and to be send simultaniously
    """
    response = llm_with_tools.invoke([HumanMessage(content=prompt)])
    return {"messages": [response]}

# Router to decide the next step
def should_continue(state: GraphState):
    last_message = state['messages'][-1]
    # Check if the last message from the LLM contains a tool call
    if last_message.tool_calls:
        # If it does, route to the 'tool_node' to execute the tools
        return "tools"
    else:
        # If it doesn't, we assume the LLM has a complete thought and route to 'analysis_agent'
        return "end"

# Analysis Agent
def analysis_agent(state: GraphState):
    print("---ANALYSIS AGENT: Synthesizing information and providing analysis---")
    all_messages = state['messages']
    
    prompt = f"""
    You are a senior SOC analyst. Your task is to analyze all the raw data provided below and synthesize it into a professional, final security report.
    The data includes the initial alert and the results from various investigation tools.
    
    Your final report should include:
    1. A detailed final analysis of the incident, correlating all findings.
    2. A definitive threat level classification (e.g., HIGH, MEDIUM, LOW, INFORMATIONAL).
    3. A list of recommended actions for containment, eradication, and recovery.
    if this is a malicious incident.
    if not just a simple message explainig why it is legitimate
    
    Raw data:
    {all_messages}
    
    Final Report:
    """
    response = llm.invoke([HumanMessage(content=prompt)])
    return {"final_analysis": response.content}


# --- Build the Graph ---

# Create a graph
workflow = StateGraph(GraphState)

# Define the list of tools available to the ToolNode
tools = [get_virustotal_report, check_abuseipdb, get_geoip_location]
tool_node = ToolNode(tools)

# Add the nodes to the graph
workflow.add_node("triage_agent", triage_agent)
workflow.add_node("tool_node", tool_node)
workflow.add_node("analysis_agent", analysis_agent)

# Set the entry point and the conditional edges
workflow.add_edge(START, "triage_agent")

# The triage agent's output is checked by the should_continue router
workflow.add_conditional_edges(
    "triage_agent",
    should_continue,
    {
        "tools": "tool_node",
        "end": "analysis_agent"
    }
)

# After the tool_node executes, the flow always proceeds to the analysis agent
workflow.add_edge("tool_node", "analysis_agent")

# The final analysis agent is the end of the graph's workflow
workflow.add_edge("analysis_agent", END)

# Compile the graph
app = workflow.compile()

# --- Run the application ---
if __name__ == "__main__":
    initial_alert = "Impossible Travel Alert for user jdoe@example.com: A session was initiated from IP 104.28.21.31 (New York, USA) at 15:30:10 EST, followed by a successful login from IP 45.137.234.19 (Moscow, Russia) at 15:32:45 EST. The two events are separated by a time difference of 2 minutes and 35 seconds, making physical travel impossible."

    # Run the graph and print the output for each step
    for chunk in app.stream({"initial_alert": initial_alert}):
        print("---")
        text = str(chunk).replace("\\n", "\n")
        print("Chunk:", text)
        print("---")

    '''# Run the graph and print the final output
    final_output = app.invoke({"initial_alert": initial_alert})
    print("\n---FINAL REPORT---")
    print(final_output['final_analysis'])'''