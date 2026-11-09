/*
 * CyberGuard AI - defense workflow (extracted from the legacy template in
 * Stage 2; behaviour identical to the released code).
 *
 * Every state-changing call carries the session CSRF token; the approval
 * token never touches storage or the DOM. Preview -> approve -> execute
 * remain separate explicit steps, and all read-only inspections are
 * on-demand only.
 */
(function () {
    "use strict";

    var panel = document.getElementById("defense-panel");
    if (!panel) {
        return;
    }

    var statusEl = document.getElementById("defense-status");
    var inspectionBox = document.getElementById("defense-inspection");
    var form = document.getElementById("defense-form");
    var previewButton = document.getElementById("defense-preview-button");
    var previewBox = document.getElementById("defense-preview");
    var resultBox = document.getElementById("defense-result");
    var auditBox = document.getElementById("defense-audit");
    var auditStatus = document.getElementById("audit-status");
    var overviewReadiness = document.getElementById("overview-readiness");
    var networkBox = document.getElementById("network-results");
    var networkStatus = document.getElementById("network-status");
    var firewallBox = document.getElementById("firewall-status-results");
    var firewallMessage = document.getElementById("firewall-status-message");

    // The approval token lives only in this closure. It is never rendered,
    // stored in the DOM or written to localStorage.
    var currentAction = null;
    var approvalToken = null;
    var csrfToken = null;
    var csrfHeader = "X-CyberGuard-CSRF";

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined && text !== null) {
            node.textContent = String(text);
        }
        return node;
    }

    function clear(node) {
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    function badge(text, className) {
        return el("span", "badge " + className, text);
    }

    function stateChanging(options) {
        var method = (options && options.method) || "GET";
        return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
    }

    function requestOnce(path, options) {
        return fetch(path, options).then(function (response) {
            return response.json().catch(function () {
                return {};
            }).then(function (data) {
                if (!response.ok) {
                    var error = new Error(
                        data.error || ("Request failed (" + response.status + ").")
                    );
                    error.category = data.error_category || "";
                    throw error;
                }
                return data;
            });
        });
    }

    function bootstrapCsrf() {
        return fetch("/api/defense/status").then(function (response) {
            return response.json();
        }).then(function (data) {
            csrfToken = data.csrf_token || csrfToken;
            csrfHeader = data.csrf_header || csrfHeader;
            return data;
        });
    }

    function api(path, options) {
        options = options || {};
        if (stateChanging(options)) {
            options.headers = Object.assign({}, options.headers || {});
            if (csrfToken) {
                options.headers[csrfHeader] = csrfToken;
            }
        }
        return requestOnce(path, options).catch(function (error) {
            if (error.category === "csrf_required" && stateChanging(options)) {
                return bootstrapCsrf().then(function () {
                    options.headers[csrfHeader] = csrfToken;
                    return requestOnce(path, options);
                });
            }
            throw error;
        });
    }

    function showError(container, error) {
        clear(container);
        var box = el("div", "defense-box");
        box.appendChild(el("p", "defense-fail",
            "Request failed: " + (error.message || "unknown error")));
        if (error.category) {
            box.appendChild(el("p", "defense-kv",
                "Error category: " + error.category));
        }
        container.appendChild(box);
    }

    function makeTable(caption, headers, rows) {
        var table = el("table", "batch-table");
        table.appendChild(el("caption", null, caption));

        var head = el("thead");
        var headRow = el("tr");
        headers.forEach(function (header) {
            headRow.appendChild(el("th", null, header));
        });
        head.appendChild(headRow);
        table.appendChild(head);

        var body = el("tbody");
        rows.forEach(function (row) {
            var tr = el("tr");
            row.forEach(function (value) {
                tr.appendChild(el("td", null,
                    value === null || value === undefined ? "—" : value));
            });
            body.appendChild(tr);
        });
        table.appendChild(body);
        return table;
    }

    // ------------------------------------------------------------ status

    function loadStatus() {
        return api("/api/defense/status").then(function (data) {
            csrfToken = data.csrf_token || csrfToken;
            csrfHeader = data.csrf_header || csrfHeader;

            var elevation = data.elevation || {};
            var registry = data.rules_registry || {};
            var text = "Platform: " + data.platform +
                " · Active CyberGuard rules: " + data.rules_active +
                " · Audit events: " + data.audit.events +
                " · Elevation: " +
                (elevation.enabled ? "enabled" : "disabled") + ". ";
            if (elevation.configured && !elevation.trusted) {
                text += "Elevation is configured but refused. ";
            }
            if (registry.healthy === false) {
                text += "Ownership registry problem: " +
                    (registry.error || "invalid records") + " ";
            }
            statusEl.textContent = text + (elevation.detail || "");

            if (overviewReadiness) {
                overviewReadiness.textContent =
                    "Local inspection readiness: platform " + data.platform +
                    " · elevation " +
                    (elevation.enabled ? "enabled" : "disabled") +
                    " · " + data.rules_active +
                    " active CyberGuard rule(s) · " + data.audit.events +
                    " audit event(s). Process, connection and firewall " +
                    "checks run only on demand.";
            }

            var limitationsBox = document.getElementById(
                "defense-limitations"
            );
            if (limitationsBox) {
                clear(limitationsBox);
                limitationsBox.appendChild(el("h3", null,
                    "Known limitations"));
                (data.limitations || []).forEach(function (limitation) {
                    limitationsBox.appendChild(el("p", "defense-warning",
                        limitation));
                });
            }
        }).catch(function (error) {
            statusEl.textContent = "Status error: " + error.message;
        });
    }

    // -------------------------------------------------------- inspection

    function renderInspection(data) {
        clear(inspectionBox);

        if (!data.available) {
            var failure = el("div", "defense-box");
            failure.appendChild(el("p", "defense-fail",
                data.error || "Inspection failed."));
            if (data.error_category) {
                failure.appendChild(el("p", "defense-kv",
                    "Error category: " + data.error_category));
            }
            inspectionBox.appendChild(failure);
            return;
        }

        var box = el("div", "defense-box");
        box.appendChild(el("p", "defense-kv",
            "Read-only result. No system state was changed."));

        if (data.action_type === "list_processes") {
            box.appendChild(makeTable(
                "Processes (" + data.count + " shown)",
                ["Name", "PID", "Session", "Memory"],
                data.processes.map(function (row) {
                    return [row.name, row.pid, row.session, row.memory];
                })
            ));
        } else if (data.action_type === "list_network_connections") {
            box.appendChild(makeTable(
                "Connections (" + data.count + " shown)",
                ["Protocol", "Local", "Remote", "State", "PID"],
                data.connections.map(function (row) {
                    return [row.protocol, row.local, row.remote,
                        row.state, row.pid];
                })
            ));
        } else if (data.action_type === "get_firewall_status") {
            box.appendChild(makeTable(
                "Firewall profiles",
                ["Profile", "Enabled"],
                data.profiles.map(function (row) {
                    return [row.profile, row.enabled ? "ON" : "OFF"];
                })
            ));
            if (!data.parsed) {
                box.appendChild(el("p", "defense-warning",
                    "The profile state could not be parsed; raw output is shown."));
            }
        } else {
            box.appendChild(el("pre", "defense-json",
                JSON.stringify(data, null, 2)));
        }

        inspectionBox.appendChild(box);
    }

    function runInspection(actionType, params) {
        clear(inspectionBox);
        inspectionBox.appendChild(el("p", "hint",
            "Running a fixed read-only command..."));

        api("/api/defense/inspect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action_type: actionType,
                params: params || {}
            })
        }).then(renderInspection).catch(function (error) {
            showError(inspectionBox, error);
        });
    }

    document.getElementById("defense-refresh").addEventListener("click", loadStatus);
    document.getElementById("defense-processes").addEventListener("click", function () {
        runInspection("list_processes", { limit: 25 });
    });

    // ------------------------------------------- network activity section

    function loadNetworkActivity() {
        clear(networkBox);
        networkStatus.textContent =
            "Running the fixed read-only netstat command...";
        networkBox.appendChild(el("p", "hint", "Loading snapshot..."));

        api("/api/defense/inspect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action_type: "list_network_connections",
                params: { limit: 100, protocol: "all" }
            })
        }).then(function (data) {
            clear(networkBox);
            networkStatus.textContent = "";

            if (!data.available) {
                networkBox.appendChild(el("p", "defense-fail",
                    data.error || "Network inspection failed."));
                if (data.error_category) {
                    networkBox.appendChild(el("p", "defense-kv",
                        "Error category: " + data.error_category));
                }
                return;
            }

            networkBox.appendChild(el("p", "defense-kv",
                "Read-only snapshot. No system state was changed."));
            networkBox.appendChild(makeTable(
                "Active connections (" + data.count + " shown of " +
                data.limit + " requested)",
                ["Protocol", "Local", "Remote", "State", "PID"],
                (data.connections || []).map(function (row) {
                    return [row.protocol, row.local, row.remote,
                        row.state, row.pid];
                })
            ));
            if (data.truncated) {
                networkBox.appendChild(el("p", "defense-warning",
                    "The snapshot was truncated at the requested limit."));
            }
            networkBox.appendChild(el("p", "hint",
                "Process names are not resolved by this read-only view; " +
                "only the PID is shown."));
        }).catch(function (error) {
            clear(networkBox);
            networkStatus.textContent = "";
            showError(networkBox, error);
        });
    }

    // --------------------------------------------- firewall status section

    function renderFirewallStatus(data) {
        clear(firewallBox);
        firewallMessage.textContent = "";

        if (!data.available) {
            firewallBox.appendChild(el("p", "defense-fail",
                data.error || "Firewall status check failed."));
            if (data.error_category) {
                firewallBox.appendChild(el("p", "defense-kv",
                    "Error category: " + data.error_category));
            }
            return;
        }

        firewallBox.appendChild(el("p", "defense-kv",
            "Read-only status. No firewall rule or profile was changed."));

        var profiles = data.profiles || [];
        if (profiles.length) {
            firewallBox.appendChild(makeTable(
                "Firewall profiles",
                ["Profile", "State"],
                profiles.map(function (row) {
                    return [row.profile, row.enabled ? "ON" : "OFF"];
                })
            ));
        } else {
            firewallBox.appendChild(el("p", "defense-warning",
                "No profile state could be identified. This is not a claim " +
                "that the firewall is off."));
        }

        if (!data.parsed) {
            firewallBox.appendChild(el("p", "defense-warning",
                "The localised output could not be parsed. Raw text is " +
                "shown below instead of guessing."));
            if (data.raw) {
                firewallBox.appendChild(el("pre", "defense-json", data.raw));
            }
        }
        if (data.note) {
            firewallBox.appendChild(el("p", "hint", data.note));
        }
        firewallBox.appendChild(el("p", "hint",
            "Displaying status does not modify Windows Firewall. Any change " +
            "requires a separately previewed and approved action."));
    }

    function loadFirewallStatus() {
        clear(firewallBox);
        firewallMessage.textContent =
            "Running the fixed read-only firewall status command...";
        firewallBox.appendChild(el("p", "hint", "Loading snapshot..."));

        api("/api/defense/inspect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action_type: "get_firewall_status",
                params: { include_raw: true }
            })
        }).then(function (data) {
            renderFirewallStatus(data);
        }).catch(function (error) {
            clear(firewallBox);
            firewallMessage.textContent = "";
            showError(firewallBox, error);
        });
    }

    var networkButton = document.getElementById("network-refresh");
    if (networkButton) {
        networkButton.addEventListener("click", loadNetworkActivity);
    }

    var firewallButton = document.getElementById("firewall-refresh");
    if (firewallButton) {
        firewallButton.addEventListener("click", loadFirewallStatus);
    }

    // ----------------------------------------------------------- preview

    function readPort(id) {
        var value = document.getElementById(id).value.trim();
        return value === "" ? null : value;
    }

    function buildParams() {
        var params = {
            remote_address: document.getElementById("defense-address").value.trim(),
            protocol: document.getElementById("defense-protocol").value,
            direction: document.getElementById("defense-direction").value,
            profile: document.getElementById("defense-profile").value
        };

        var localPort = readPort("defense-port");
        if (localPort !== null) {
            params.local_port = localPort;
        }

        var remotePort = readPort("defense-remote-port");
        if (remotePort !== null) {
            params.remote_port = remotePort;
        }

        var lifetime = document.getElementById("defense-lifetime").value.trim();
        if (lifetime !== "") {
            if (!/^\d+$/.test(lifetime)) {
                throw new Error("Lifetime must be a whole number of minutes.");
            }
            params.lifetime_minutes = Number(lifetime);
        }

        return params;
    }

    function renderPreview(data) {
        clear(previewBox);
        clear(resultBox);
        approvalToken = null;

        var action = data.action || {};
        var preview = data.preview || {};
        var box = el("div", "defense-box");

        box.appendChild(el("h3", null, preview.title || action.action_type));

        var badges = el("p");
        badges.appendChild(badge(
            "Risk: " + (preview.risk || "unknown"),
            "badge-risk"
        ));
        badges.appendChild(document.createTextNode(" "));
        badges.appendChild(badge(
            preview.requires_admin
                ? "Administrator required"
                : "No administrator rights",
            preview.requires_admin ? "badge-admin" : "badge-safe"
        ));
        badges.appendChild(document.createTextNode(" "));
        badges.appendChild(badge(
            preview.rollback_supported
                ? "Rollback supported"
                : "No rollback",
            preview.rollback_supported ? "badge-safe" : "badge-risk"
        ));
        box.appendChild(badges);

        box.appendChild(el("p", "defense-kv",
            "Target: " + (preview.target || "—")));
        box.appendChild(el("p", "defense-kv",
            preview.expected_effect || ""));

        if (preview.idempotent) {
            box.appendChild(el("p", "defense-kv",
                "A CyberGuard rule for this exact scope already exists; " +
                "execution will reuse it."));
        }

        (preview.warnings || []).forEach(function (warning) {
            box.appendChild(el("p", "defense-warning", warning));
        });

        box.appendChild(el("p", "defense-warning",
            "lifetime_minutes is recorded for audit/rollback only. The rule " +
            "does NOT expire or get removed automatically."));

        box.appendChild(el("p", "defense-kv", "Exact canonical parameters:"));
        box.appendChild(el("pre", "defense-json",
            JSON.stringify(preview.params || {}, null, 2)));

        box.appendChild(el("p", "hint",
            "Prepared action expires at " + (preview.expires_at || "—") +
            ". Approval is a separate, explicit step."));

        var approveButton = el("button", null, "Approve This Exact Action");
        approveButton.type = "button";
        approveButton.addEventListener("click", function () {
            approveButton.disabled = true;
            approveAction(action);
        });
        box.appendChild(approveButton);

        previewBox.appendChild(box);
    }

    function approveAction(action) {
        api("/api/defense/actions/" + encodeURIComponent(action.action_id) +
            "/approve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ confirm: action.action_type })
        }).then(function (data) {
            currentAction = data.action || action;
            approvalToken = data.approval_token;
            renderApproval(data);
        }).catch(function (error) {
            showError(resultBox, error);
        });
    }

    function renderApproval(data) {
        clear(resultBox);

        var approval = data.approval || {};
        var box = el("div", "defense-box");

        box.appendChild(el("h3", null, "Approved"));
        box.appendChild(el("p", "defense-kv",
            "This approval is single-use and expires at " +
            (approval.expires_at || "—") + "."));
        box.appendChild(el("p", "defense-warning",
            "Execution is still a separate step. Only the backend result " +
            "below is treated as success."));

        var executeButton = el("button", null, "Execute Approved Action");
        executeButton.type = "button";
        executeButton.addEventListener("click", function () {
            executeButton.disabled = true;
            executeAction();
        });

        var cancelButton = el("button", null, "Cancel This Action");
        cancelButton.type = "button";
        cancelButton.addEventListener("click", function () {
            cancelButton.disabled = true;
            cancelAction();
        });

        box.appendChild(executeButton);
        box.appendChild(document.createTextNode(" "));
        box.appendChild(cancelButton);

        resultBox.appendChild(box);
    }

    function executeAction() {
        if (!currentAction || !approvalToken) {
            showError(resultBox, new Error(
                "No approved action is available. Preview and approve again."
            ));
            return;
        }

        var actionId = currentAction.action_id;
        api("/api/defense/actions/" + encodeURIComponent(actionId) +
            "/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ approval_token: approvalToken })
        }).then(function (result) {
            approvalToken = null;
            renderExecution(result);
            loadAudit();
            loadStatus();
        }).catch(function (error) {
            approvalToken = null;
            showError(resultBox, error);
            loadAudit();
        });
    }

    function renderExecution(result) {
        clear(resultBox);

        var status = result.status || "unknown";
        var verified = result.verified;
        var verifiedText = (verified === null || verified === undefined)
            ? "not reported"
            : (verified ? "yes" : "no");

        var headline;
        var className;
        var explanation;

        if (status === "success" && verified === true) {
            headline = "Verified success";
            className = "defense-ok";
            explanation = "The backend verified the exact firewall state. " +
                "Review the audit history below.";
        } else if (status === "success" || status === "unverified") {
            headline = "Unverified result";
            className = "defense-warning";
            explanation = "The backend returned a success-like status but " +
                "did NOT verify the resulting firewall state. Do not treat " +
                "this as a confirmed change.";
        } else if (status === "execution_unknown") {
            headline = "Execution outcome unknown";
            className = "defense-warning";
            explanation = "The helper did not return a verified result. It " +
                "may still be running and may have changed the firewall. " +
                "This action will not be retried automatically; reconcile " +
                "the firewall state and review the audit log.";
        } else if (status === "cancelled") {
            headline = "Cancelled";
            className = "defense-warning";
            explanation = "The action was cancelled; nothing is claimed to " +
                "have changed.";
        } else {
            headline = "Failure";
            className = "defense-fail";
            explanation = "The backend did not confirm success. Nothing is " +
                "claimed to have changed.";
        }

        var box = el("div", "defense-box");
        box.appendChild(el("h3", null, "Execution Result"));
        box.appendChild(el("p", className, headline +
            " · Backend status: " + status));
        box.appendChild(el("p", "defense-kv",
            "State changed: " + (result.changed ? "yes" : "no") +
            " · Verified: " + verifiedText +
            " · Elevation: " + (result.elevation || "not required")));

        if (result.error) {
            box.appendChild(el("p", "defense-fail", result.error));
        }
        if (result.error_category) {
            box.appendChild(el("p", "defense-kv",
                "Error category: " + result.error_category));
        }
        if (result.detail && result.detail.reason) {
            box.appendChild(el("p", "defense-kv",
                "Unresolved reason: " + result.detail.reason));
        }

        box.appendChild(el("p", "defense-kv", explanation));

        resultBox.appendChild(box);
    }

    function cancelAction() {
        if (!currentAction) {
            return;
        }

        api("/api/defense/actions/" +
            encodeURIComponent(currentAction.action_id) + "/cancel", {
            method: "POST"
        }).then(function () {
            approvalToken = null;
            clear(resultBox);
            var box = el("div", "defense-box");
            box.appendChild(el("h3", null, "Cancelled"));
            box.appendChild(el("p", "defense-kv",
                "This action was cancelled and its approval was revoked. " +
                "It can never execute."));
            resultBox.appendChild(box);
            loadAudit();
        }).catch(function (error) {
            showError(resultBox, error);
        });
    }

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        var params;
        try {
            params = buildParams();
        } catch (error) {
            showError(previewBox, error);
            return;
        }

        clear(previewBox);
        clear(resultBox);
        currentAction = null;
        approvalToken = null;

        previewButton.disabled = true;
        previewBox.appendChild(el("p", "hint", "Preparing a preview..."));

        api("/api/defense/actions/preview", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action_type: "create_firewall_block_rule",
                params: params
            })
        }).then(function (data) {
            currentAction = data.action || null;
            renderPreview(data);
        }).catch(function (error) {
            showError(previewBox, error);
        }).finally(function () {
            previewButton.disabled = false;
        });
    });

    // ------------------------------------------------------------- audit

    function loadAudit() {
        if (auditStatus) {
            auditStatus.textContent = "Loading action history...";
        }

        return api("/api/defense/audit?limit=25").then(function (data) {
            clear(auditBox);
            if (auditStatus) {
                auditStatus.textContent = "";
            }

            var events = data.events || [];
            if (!events.length) {
                auditBox.appendChild(el("p", "hint", "No audit events yet."));
                return;
            }

            auditBox.appendChild(makeTable(
                "Newest first",
                ["Timestamp", "Event", "Action", "Target", "Outcome",
                 "Approval", "Elevation", "Error"],
                events.map(function (event) {
                    return [
                        event.timestamp,
                        event.event_type,
                        event.action_type || "—",
                        event.target || "—",
                        event.outcome,
                        event.approval || "—",
                        event.elevation || "—",
                        event.error_category || "—"
                    ];
                })
            ));
            auditBox.appendChild(el("p", "hint",
                "Total recorded events: " + data.count +
                (data.truncated
                    ? " · The read window is limited; older events exist."
                    : "")));
            auditBox.appendChild(el("p", "hint",
                "An outcome of success means the backend reported success. " +
                "Check the execution result panel for whether the exact " +
                "firewall state was verified."));
        }).catch(function (error) {
            if (auditStatus) {
                auditStatus.textContent = "";
            }
            showError(auditBox, error);
        });
    }

    document.getElementById("defense-audit-refresh").addEventListener(
        "click", loadAudit
    );

    loadStatus();
    loadAudit();
})();
