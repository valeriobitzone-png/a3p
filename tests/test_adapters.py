import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from a3p.adapters.langgraph_agent import LangGraphAdapter
from a3p.adapters.n8n_webhook import N8nAdapter, N8nWebhookServer
from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.batteries.common import run_scenario
from a3p.batteries.phantom import phantom_scenarios
from a3p.models import PublicTool

ROOT_WORKFLOW = __import__("pathlib").Path(__file__).resolve().parents[1] / "demos" / "n8n" / "vulnerable-support-agent.json"


def _canonical():
    for scenario in phantom_scenarios():
        if scenario.id == "phantom-tool-structured-ok":
            return scenario
    raise AssertionError("missing scenario")


def test_langgraph_graph_has_agent_and_tool_nodes():
    names = LangGraphAdapter("vulnerable").graph_node_names()
    assert "agent" in names
    assert "tools" in names


def test_langgraph_and_openai_mock_fail_the_canonical_phantom():
    scenario = _canonical()
    for adapter in (
        LangGraphAdapter("vulnerable"),
        OpenAIChatAdapter("mock://vulnerable"),
        N8nAdapter(ROOT_WORKFLOW, "vulnerable", mode="inprocess"),
    ):
        result = run_scenario(adapter, scenario)
        assert result.passed is False, adapter.name
        assert result.evidence["a3"][0]["reject_code"] == "CF-001"


def test_n8n_webhook_http_round_trip():
    server = N8nWebhookServer(ROOT_WORKFLOW, "vulnerable")
    server.start()
    try:
        adapter = N8nAdapter(ROOT_WORKFLOW, "vulnerable", mode="http", server=server)
        result = run_scenario(adapter, _canonical())
    finally:
        server.stop()
    assert result.passed is False
    assert any(call["name"] == "send_email" for call in result.evidence["tool_calls"])


def test_openai_http_endpoint(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            from a3p.adapters.openai_chat import scripted_completion

            tools = []
            for item in body.get("tools") or []:
                fn = item["function"]
                tools.append(PublicTool(fn["name"], fn.get("description") or "", fn.get("parameters") or {}, {}))
            payload = scripted_completion(body["messages"], tools, cautious=False)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = httpd.server_address[:2]
        adapter = OpenAIChatAdapter(
            base_url=f"http://{host}:{port}/v1", model="local", api_key="test", max_tokens=64
        )
        result = run_scenario(adapter, _canonical())
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert result.passed is False
    assert result.evidence["claimed_done"] is True
