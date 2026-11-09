/*
 * CyberGuard AI - AI Companion (extracted from the legacy template in
 * Stage 2; behaviour identical to the released Phase 2.1 code).
 *
 * Advisory-only conversation over POST /api/chat with session continuation,
 * mode pills (companion/security), New-chat reset, expired-session handling
 * and textContent-only rendering. Nothing is persisted.
 */
(function () {
    "use strict";

    var root = document.getElementById("companion-chat");
    var form = document.getElementById("cc-form");
    if (!root || !form) {
        return;
    }

    var input = document.getElementById("cc-input");
    var sendButton = document.getElementById("cc-send");
    var newChatButton = document.getElementById("cc-new-chat");
    var messages = document.getElementById("cc-messages");
    var status = document.getElementById("cc-status");
    var modeLabel = document.getElementById("cc-mode-label");
    var modeButtons = [
        document.getElementById("cc-mode-companion"),
        document.getElementById("cc-mode-security")
    ];

    // Browser-owned conversation state. Nothing is persisted: the session id
    // and the transcript live only in this page's memory and disappear on
    // reload, "New chat", or server-side session expiry.
    var sessionId = null;
    var activeMode = "companion";
    var busy = false;

    var MODE_NOTES = {
        companion: "Companion mode: everyday conversation, general security "
            + "questions, empathetic replies.",
        security: "Security mode: analysis coaching and formal, "
            + "evidence-focused guidance. Use the Analyze panel for a "
            + "specific log."
    };

    function setBusy(pending) {
        busy = pending;
        sendButton.disabled = pending;
        newChatButton.disabled = pending;
        status.classList.toggle("cc-thinking", pending);
    }

    function setStatus(text) {
        status.textContent = text;
    }

    function clearMessages() {
        while (messages.firstChild) {
            messages.removeChild(messages.firstChild);
        }
    }

    function appendMessage(role, text, meta) {
        var wrapper = document.createElement("div");
        wrapper.className = "cc-msg cc-msg-" + role;

        var bubble = document.createElement("p");
        bubble.className = "cc-bubble";
        // textContent only: conversation text (user or model) is untrusted
        // and must never be parsed as HTML.
        bubble.textContent = text;
        wrapper.appendChild(bubble);

        if (meta) {
            var note = document.createElement("p");
            note.className = "cc-meta";
            note.textContent = meta;
            wrapper.appendChild(note);
        }

        messages.appendChild(wrapper);
        messages.scrollTop = messages.scrollHeight;
    }

    function metaLine(data) {
        var parts = [];
        if (data.mode) {
            parts.push("mode: " + data.mode);
        }
        if (data.provider) {
            parts.push("provider: " + data.provider);
        }
        if (data.model) {
            parts.push("model: " + data.model);
        }
        if (data.history_used) {
            parts.push("context: " + data.history_used + " earlier turn(s)");
        }
        if (data.error) {
            parts.push("fallback: " + data.error);
        }
        parts.push("advisory only - no actions taken");
        return parts.join(" \u00b7 ");
    }

    function resetConversation() {
        sessionId = null;
        clearMessages();
        setStatus("New conversation started. Nothing is stored.");
    }

    function updateModeLabel(clearedSession) {
        modeLabel.textContent = MODE_NOTES[activeMode]
            + " Selected mode: " + activeMode + ".";
        if (clearedSession) {
            // Never mix modes inside one session: switching starts fresh.
            resetConversation();
            setStatus("Mode changed - started a new conversation.");
        }
    }

    function setMode(mode) {
        if (busy || mode === activeMode) {
            return;
        }

        var hadSession = sessionId !== null;
        activeMode = mode;

        for (var index = 0; index < modeButtons.length; index++) {
            var button = modeButtons[index];
            var pressed = button.getAttribute("data-mode") === mode;
            button.classList.toggle("cc-active", pressed);
            button.setAttribute("aria-pressed", pressed ? "true" : "false");
        }

        updateModeLabel(hadSession);
    }

    newChatButton.addEventListener("click", function () {
        if (busy) {
            return;
        }
        resetConversation();
        input.focus();
    });

    for (var buttonIndex = 0; buttonIndex < modeButtons.length;
         buttonIndex++) {
        (function (button) {
            button.addEventListener("click", function () {
                setMode(button.getAttribute("data-mode"));
            });
        })(modeButtons[buttonIndex]);
    }

    input.addEventListener("keydown", function (event) {
        // Enter sends, Shift+Enter inserts a newline (default behaviour).
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            if (!sendButton.disabled) {
                if (form.requestSubmit) {
                    form.requestSubmit();
                } else {
                    sendButton.click();
                }
            }
        }
    });

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        // Duplicate submissions are impossible while a request is pending:
        // the guard and the disabled button are checked before sending.
        if (busy) {
            return;
        }

        var text = input.value.trim();
        if (!text) {
            setStatus("Type a message first.");
            return;
        }

        setBusy(true);
        setStatus("Preparing your response\u2026");

        var payload = { message: text, mode: activeMode };
        if (sessionId) {
            payload.session_id = sessionId;
        }

        fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        }).then(function (response) {
            return response.json().then(function (data) {
                return { ok: response.ok, status: response.status, data: data };
            });
        }).then(function (result) {
            var data = result.data || {};

            if (!result.ok) {
                var detail = data.error || "Request failed.";

                if (result.status === 404) {
                    // Session expired or ended server-side: forget it and
                    // invite the user to try again in a fresh conversation.
                    sessionId = null;
                    clearMessages();
                    setStatus(
                        "The conversation expired. A fresh one is ready - "
                        + "send your message again. (" + detail + ")"
                    );
                } else {
                    setStatus("Error: " + detail);
                }
                return;
            }

            sessionId = data.session_id;
            appendMessage("user", text);
            appendMessage(
                "assistant",
                data.reply || "(empty reply)",
                metaLine(data)
            );
            input.value = "";
            setStatus("");
        }).catch(function (error) {
            setStatus("Error: " + (error && error.message
                ? error.message : "Please try again."));
        }).finally(function () {
            setBusy(false);
            input.focus();
        });
    });

    // Show the default mode description immediately, not only after a
    // first mode switch (false: no session could exist yet).
    updateModeLabel(false);
    setStatus("Ready. Every message stays on this machine.");
})();
