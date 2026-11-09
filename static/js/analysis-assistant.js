/*
 * CyberGuard AI - log-grounded assistant chat (extracted from the legacy
 * template in Stage 2; behaviour identical to the released Phase 2.1 code).
 *
 * Advisory only: the ask flow sends {log, question, history?} to
 * POST /api/assistant and renders the answer with textContent only.
 */
(function () {
    "use strict";

    var chat = document.getElementById("assistant-chat");
    var form = document.getElementById("chat-form");
    if (!chat || !form) {
        return;
    }

    var input = document.getElementById("chat-question");
    var button = document.getElementById("chat-send");
    var status = document.getElementById("chat-status");
    var transcript = document.getElementById("chat-transcript");
    var memory = document.getElementById("chat-memory");
    var clearButton = document.getElementById("chat-clear");

    // Browser-owned conversation. Never persisted; cleared with the button or
    // by reloading the page. Only sent when the user ticks the memory box.
    var conversation = [];
    var MAX_HISTORY_MESSAGES = 8;

    function addMessage(role, text, meta) {
        var wrapper = document.createElement("div");
        wrapper.className = "chat-msg chat-" + role;

        var bubble = document.createElement("p");
        bubble.className = "chat-text";
        // textContent (never innerHTML): knowledge-base text is untrusted.
        bubble.textContent = text;
        wrapper.appendChild(bubble);

        if (meta) {
            var note = document.createElement("p");
            note.className = "chat-meta";
            note.textContent = meta;
            wrapper.appendChild(note);
        }

        transcript.appendChild(wrapper);

        conversation.push({ role: role, content: text });
        if (conversation.length > MAX_HISTORY_MESSAGES) {
            conversation.splice(0, conversation.length - MAX_HISTORY_MESSAGES);
        }
    }

    function buildMeta(assistant) {
        var parts = ["provider: " + (assistant.provider || "unknown")];
        if (assistant.model) {
            parts.push("model: " + assistant.model);
        }
        if (assistant.history_used) {
            parts.push("memory: " + assistant.history_used +
                " earlier message(s)");
        }
        if (assistant.error) {
            parts.push("fallback: " + assistant.error);
        }
        if (assistant.citations && assistant.citations.length) {
            parts.push("sources: " + assistant.citations.map(function (citation) {
                return "[" + citation.index + "] " + citation.category +
                    " / " + citation.section;
            }).join(", "));
        }
        return parts.join(" \u00b7 ");
    }

    clearButton.addEventListener("click", function () {
        conversation = [];
        transcript.textContent = "";
        status.textContent = "Conversation cleared.";
        input.focus();
    });

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        var log = (chat.getAttribute("data-log") || "").trim();
        var question = input.value.trim();

        if (!log) {
            status.textContent = "Analyze a log first, then ask a question.";
            return;
        }
        if (!question) {
            status.textContent = "Type a question first.";
            return;
        }

        // Snapshot history before adding the current question: the API takes
        // the new question separately.
        var history = memory && memory.checked ? conversation.slice() : [];

        addMessage("user", question);
        input.value = "";
        button.disabled = true;
        status.textContent = "Preparing your response\u2026";

        var payload = { log: log, question: question };
        if (history.length) {
            payload.history = history;
        }

        fetch("/api/assistant", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        }).then(function (response) {
            return response.json().then(function (data) {
                if (!response.ok) {
                    throw new Error(data.error || "Request failed.");
                }
                return data;
            });
        }).then(function (data) {
            var assistant = data.assistant || {};
            addMessage(
                "assistant",
                assistant.answer || "(empty answer)",
                buildMeta(assistant)
            );
            status.textContent = "";
        }).catch(function (error) {
            status.textContent = "Error: " + error.message;
        }).finally(function () {
            button.disabled = false;
            input.focus();
        });
    });
})();
