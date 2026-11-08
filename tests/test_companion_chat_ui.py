"""Frontend integration tests for the companion chat UI (Step 5).

These follow the dashboard-sections convention: they inspect the rendered
HTML and the JavaScript conventions the UI relies on; they never execute
JavaScript and never touch a real model or network.
"""

import pytest

import app as app_module


CC_SCRIPT_START = 'var root = document.getElementById("companion-chat")'

ANALYSIS_LOG = "Failed password for admin from 10.0.0.5 port 22 ssh2"


@pytest.fixture
def html_with_log(monkeypatch):
    monkeypatch.setattr(app_module, "build_context", lambda *a, **k: {
        "query": "", "mode": "hybrid", "available": False,
        "passages": [], "truncated": False, "error": "test",
    })
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client.post("/", data={"log": ANALYSIS_LOG}).get_data(
            as_text=True
        )


@pytest.fixture
def html_without_log():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client.get("/").get_data(as_text=True)


def companion_script(html):
    """Return the companion-chat script block only (never the defense JS)."""
    start = html.find(CC_SCRIPT_START)
    assert start != -1, "companion chat script missing from the page"

    end = html.find("<script>", start)
    assert end != -1, "companion chat script is not terminated"

    return html[start:end]


def test_companion_chat_is_always_present_without_a_log(html_without_log):
    # Works with no log uploaded at all: the section is outside the
    # log-conditional block.
    assert 'id="companion-chat"' in html_without_log
    assert 'id="cc-form"' in html_without_log
    assert 'id="cc-input"' in html_without_log
    assert 'id="cc-send"' in html_without_log
    assert 'id="cc-new-chat"' in html_without_log
    assert 'id="cc-messages"' in html_without_log
    assert 'id="cc-status"' in html_without_log


def test_both_modes_are_offered_and_companion_is_default(html_without_log):
    assert 'id="cc-mode-companion"' in html_without_log
    assert 'id="cc-mode-security"' in html_without_log
    assert 'data-mode="companion"' in html_without_log
    assert 'data-mode="security"' in html_without_log

    start = html_without_log.find('id="cc-mode-companion"')
    tag = html_without_log[start:start + 160]
    assert "cc-active" in tag
    assert 'aria-pressed="true"' in tag

    security_start = html_without_log.find('id="cc-mode-security"')
    security_tag = html_without_log[security_start:security_start + 160]
    assert "cc-active" not in security_tag
    assert 'aria-pressed="false"' in security_tag


def test_mode_switch_never_silently_keeps_a_session(html_without_log):
    script = companion_script(html_without_log)

    assert "activeMode = mode;" in script
    assert "Mode changed - started a new conversation." in script
    assert "resetConversation()" in script


def test_mode_label_is_initialised_on_load(html_without_log):
    script = companion_script(html_without_log)

    # The default (companion) mode description is rendered at startup,
    # not only after the user first clicks a mode.
    assert "updateModeLabel(false);" in script
    init_position = script.find("updateModeLabel(false);")
    function_position = script.find("function updateModeLabel(")
    start_position = script.find('setStatus("Ready.')
    assert 0 < function_position < init_position < start_position


def test_chat_posts_to_api_chat_with_session_continuation(html_without_log):
    script = companion_script(html_without_log)

    assert 'fetch("/api/chat"' in script
    assert "message: text, mode: activeMode" in script
    assert "payload.session_id = sessionId;" in script
    # The returned session id is adopted for subsequent turns.
    assert "sessionId = data.session_id;" in script


def test_new_chat_resets_the_session(html_without_log):
    script = companion_script(html_without_log)

    assert 'id="cc-new-chat"' in html_without_log
    assert "function resetConversation()" in script
    assert "sessionId = null;" in script
    assert "clearMessages()" in script


def test_expired_and_missing_sessions_are_handled(html_without_log):
    script = companion_script(html_without_log)

    assert "result.status === 404" in script
    assert "The conversation expired. A fresh one is ready" in script
    assert "sessionId = null;" in script


def test_input_supports_enter_to_send_and_shift_enter_for_newline(
        html_without_log):
    script = companion_script(html_without_log)

    assert 'event.key === "Enter" && !event.shiftKey' in script
    assert "event.preventDefault()" in script
    assert "requestSubmit" in script


def test_duplicate_submissions_are_prevented(html_without_log):
    script = companion_script(html_without_log)

    assert "if (busy) {" in script
    assert "sendButton.disabled = pending;" in script
    assert "if (busy) {\n            return;\n        }" in script \
        or "if (busy) { return; }" in script \
        or "if (busy) {\n                return;\n            }" in script


def test_all_messages_are_rendered_with_textcontent(html_without_log):
    script = companion_script(html_without_log)

    assert "bubble.textContent = text;" in script
    assert "note.textContent = meta;" in script
    assert "status.textContent = text;" in script
    # No HTML-injection surface anywhere in the companion script.
    assert ".innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "document.write" not in script


def test_no_client_side_persistence(html_without_log):
    script = companion_script(html_without_log)
    # Scope strictly to the companion-chat section: it ends where the next
    # section (network activity) begins. Later scripts (defense panel etc.)
    # legitimately use other storage and are covered by their own tests.
    section_start = html_without_log.find('id="companion-chat"')
    section_end = html_without_log.find('id="network-activity"')
    assert section_start != -1 and section_end != -1 and section_end > section_start
    root_html = html_without_log[section_start:section_end]
    full = script + root_html

    assert "localStorage" not in full
    assert "sessionStorage" not in full
    assert "document.cookie" not in full
    assert "indexedDB" not in full


def test_companion_script_never_reaches_defense_actions(html_without_log):
    script = companion_script(html_without_log)

    # No route to the privileged surface and no execution machinery.
    for marker in ("/api/defense", "defen", "subprocess", "eval("):
        assert marker not in script, marker


def test_advisory_only_message_is_visible_to_users(html_without_log):
    assert "cannot approve, execute or claim" in html_without_log


def test_honest_provider_display_no_fake_llm_status(html_without_log):
    script = companion_script(html_without_log)

    # The meta line shows the real provider (e.g. deterministic) rather
    # than inventing a model status.
    assert '"provider: " + data.provider' in script \
        or "provider: \" + data.provider" in script
    # Neutral loading text: it must not claim a model/LLM is running,
    # because the deterministic provider composes without one.
    assert "Preparing your response\\u2026" in script
    assert "Thinking locally" not in script and \
        "the model runs on this machine" not in script


def test_existing_log_chat_panel_is_untouched(html_with_log, html_without_log):
    # The old analysis-grounded panel still appears only with a log.
    assert 'id="assistant-chat"' in html_with_log
    assert 'id="assistant-chat"' not in html_without_log
    assert '<input type="checkbox" id="chat-memory">' in html_with_log
    # ...while the companion chat appears on both pages.
    assert 'id="companion-chat"' in html_with_log


def test_responsive_and_visual_structure_present(html_without_log):
    # Layout elements the CSS relies on.
    assert 'class="cc-toolbar"' in html_without_log
    assert 'class="cc-actions"' in html_without_log
    assert "cc-bubble" in html_without_log
    assert "@media (max-width: 700px)" in html_without_log
    assert "cc-pulse" in html_without_log
