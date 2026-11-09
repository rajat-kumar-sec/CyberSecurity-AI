/*
 * CyberGuard AI - application shell (Stage 2 UI 2.0).
 *
 * Responsibilities:
 * - Sidebar navigation (page switching inside one application shell).
 * - Session state store: real analysis/batch results only. Nothing is
 *   synthesised; when no data exists the UI shows explicit empty states.
 * - Overview / Threat Analytics / Event Monitoring renderers, fed from
 *   the server-rendered cg-state payload and from batch/defense modules
 *   through window.CyberGuardUI.
 *
 * Rendering is textContent/appendChild only; user- and backend-derived
 * values are never interpolated as HTML.
 */
(function () {
    "use strict";

    var store = {
        analysis: null,   // {threat, risk, confidence, ts, chars, source}
        batchReports: [], // batch report objects as returned by /api/batch
        listeners: []
    };

    function $(id) {
        return document.getElementById(id);
    }

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
        if (!node) {
            return;
        }
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    /* --------------------------------------------------- state ingestion */

    function readServerState() {
        var node = $("cg-state");

        var state = {
            has_result: false,
            analyzed_at: null,
            analysis_chars: 0,
            batch_limit: null,
            form_error: null,
            result: null
        };

        if (node) {
            try {
                var parsed = JSON.parse(node.textContent || "{}");

                state.has_result = Boolean(parsed.has_result);
                state.analyzed_at = parsed.analyzed_at || null;
                state.analysis_chars = Number(parsed.analysis_chars) || 0;
                state.batch_limit = parsed.batch_limit || null;
                state.form_error = parsed.form_error || null;
                state.result = parsed.result || null;
            } catch (error) {
                // Malformed state must never break the shell.
                state.has_result = false;
            }
        }

        if (state.has_result && state.result) {
            store.analysis = {
                source: "Log analysis",
                threat: state.result.threat_type || "Unknown",
                risk: state.result.risk || "LOW",
                confidence: state.result.ml_confidence,
                ml_prediction: state.result.ml_prediction,
                ts: state.analyzed_at,
                chars: state.analysis_chars
            };
        }

        return state;
    }

    var serverState = null;

    /* ----------------------------------------------------- subscriptions */

    function subscribe(fn) {
        store.listeners.push(fn);
    }

    function publish() {
        store.listeners.forEach(function (fn) {
            try {
                fn();
            } catch (error) {
                // One broken subscriber must not break the rest.
            }
        });
    }

    /* ------------------------------------------------------ navigation */

    var pageTitles = {
        overview: "Overview",
        "log-analysis": "Log Analysis",
        analytics: "Threat Analytics",
        monitoring: "Event Monitoring",
        defense: "Defense Actions",
        audit: "Audit History",
        assistant: "AI Security Assistant",
        companion: "AI Companion",
        settings: "Settings",
        about: "About CyberGuard"
    };

    function activatePage(name, focusHeading) {
        var valid = false;

        document.querySelectorAll(".page").forEach(function (page) {
            if (page.id === "page-" + name) {
                page.classList.add("active");
                valid = true;
            } else {
                page.classList.remove("active");
            }
        });

        if (!valid) {
            return;
        }

        document.querySelectorAll(".nav-item").forEach(function (item) {
            var active = item.getAttribute("data-page") === name;
            item.classList.toggle("active", active);
            if (active) {
                item.setAttribute("aria-current", "page");
            } else {
                item.removeAttribute("aria-current");
            }
        });

        var title = $("topbar-title");
        if (title && pageTitles[name]) {
            title.textContent = pageTitles[name];
        }

        var sidebar = $("cg-sidebar");
        if (sidebar) {
            sidebar.classList.remove("nav-open");
            var toggle = $("cg-menu-toggle");
            if (toggle) {
                toggle.setAttribute("aria-expanded", "false");
            }
        }

        if (focusHeading) {
            var heading = $("page-title-" + name);
            if (heading) {
                heading.focus({ preventScroll: false });
            }
        }
        publish();
    }

    function wireNavigation() {
        document.querySelectorAll(".nav-item").forEach(function (item) {
            item.addEventListener("click", function () {
                activatePage(item.getAttribute("data-page"), true);
            });
        });

        var toggle = $("cg-menu-toggle");
        var sidebar = $("cg-sidebar");
        if (toggle && sidebar) {
            toggle.addEventListener("click", function () {
                var open = sidebar.classList.toggle("nav-open");
                toggle.setAttribute("aria-expanded", open ? "true" : "false");
            });
        }

        // Quick actions (Overview) navigate to other pages.
        document.querySelectorAll("[data-navigate]").forEach(function (node) {
            node.addEventListener("click", function () {
                activatePage(node.getAttribute("data-navigate"), true);
            });
        });
    }

    /* ------------------------------------------------------- aggregation */

    function riskTally() {
        var tally = { HIGH: 0, MEDIUM: 0, LOW: 0 };

        if (store.analysis && store.analysis.risk in tally) {
            tally[store.analysis.risk] += 1;
        }

        store.batchReports.forEach(function (report) {
            (report.risks || []).forEach(function (row) {
                if (row && row.risk in tally) {
                    tally[row.risk] += Number(row.count) || 0;
                }
            });
        });

        return tally;
    }

    function categoryTally() {
        var tally = {};

        function bump(key, count) {
            if (!key) {
                return;
            }
            tally[key] = (tally[key] || 0) + (Number(count) || 0);
        }

        if (store.analysis) {
            bump(store.analysis.threat, 1);
        }

        store.batchReports.forEach(function (report) {
            (report.threat_types || []).forEach(function (row) {
                if (row && row.threat_type !== "Unknown") {
                    bump(row.threat_type, row.count);
                }
            });
        });

        return tally;
    }

    /* ---------------------------------------------------------- Overview */

    function renderConfidenceText(analysis) {
        if (!analysis || analysis.confidence === null ||
                analysis.confidence === undefined) {
            return "—";
        }
        return (analysis.confidence * 100).toFixed(1) + "%";
    }

    function renderOverview() {
        var analysis = store.analysis;

        setText("ov-analysis-status",
            analysis ? "Complete" : "Not run");
        setText("ov-threat", analysis ? analysis.threat : "—");
        setText("ov-risk", analysis ? analysis.risk : "—");

        var riskValue = $("ov-risk");
        if (riskValue && analysis) {
            riskValue.classList.remove("risk-high", "risk-medium",
                "risk-low");
            riskValue.classList.add(
                analysis.risk === "HIGH" ? "risk-high" :
                analysis.risk === "MEDIUM" ? "risk-medium" : "risk-low"
            );
        }

        setText("ov-confidence", renderConfidenceText(analysis));
        setText("ov-when",
            analysis
                ? "Analyzed " + (analysis.ts || "unknown") + " · "
                    + (analysis.chars || 0) + " characters · not persisted"
                : "No analysis stored in this page yet");

        // ML note shown only when real data exists.
        var note = $("ov-ml-note");
        if (note) {
            if (analysis && analysis.ml_prediction) {
                note.textContent = "ML prediction: " + analysis.ml_prediction
                    + ". Statistical signal, not confirmation of an attack.";
            } else {
                note.textContent = "";
            }
        }

        renderOvEvents();
        renderSeverityChart($("ov-severity-chart"), riskTally(),
            "Severity distribution (from real session data)");
    }

    function setText(id, text) {
        var node = $(id);
        if (node) {
            node.textContent = text;
        }
    }

    function sessionEvents() {
        var events = [];

        if (store.analysis) {
            events.push({
                source: store.analysis.source,
                title: store.analysis.threat,
                risk: store.analysis.risk,
                detail: "Single-log analysis · ML: " +
                    (store.analysis.ml_prediction || "—") + " · " +
                    (store.analysis.ts || "time unknown")
            });
        }

        store.batchReports.slice().reverse().forEach(function (report) {
            events.push({
                source: "Batch",
                title: (report.filename || "log file") + " · " +
                    report.suspicious + " suspicious / " +
                    report.benign + " benign",
                risk: (report.risks && report.risks.length &&
                        report.risks[0].risk) || null,
                detail: report.lines_analyzed + " of " + report.lines_total +
                    " lines" + (report.truncated
                        ? " (truncated at " + report.limit + ")" : "")
            });
        });

        return events.reverse(); // newest first
    }

    function renderOvEvents() {
        var list = $("ov-recent-events");
        if (!list) {
            return;
        }
        clear(list);

        var events = sessionEvents();
        if (!events.length) {
            list.appendChild(el("p", "hint",
                "No events yet — run an analysis or upload a batch file."));
            return;
        }

        var ul = el("ul", "timeline");
        events.slice(0, 8).forEach(function (event) {
            var li = el("li");
            if (event.risk) {
                li.setAttribute("data-risk", event.risk);
            }
            li.appendChild(el("div", "timeline-title", event.title));

            var meta = el("div", "timeline-meta", event.source +
                " · " + event.detail);
            li.appendChild(meta);
            ul.appendChild(li);
        });
        list.appendChild(ul);
    }

    /* ---------------------------------------------------------- charts */

    var SVG_NS = "http://www.w3.org/2000/svg";

    var CHART_COLORS = {
        HIGH: "#dc2626",
        MEDIUM: "#d97706",
        LOW: "#16a34a",
        category: "#2563eb"
    };

    // Inline SVG bar chart (no external chart library, no innerHTML).
    // rows: [{label, value, ratio, color}]
    function buildBarSvg(rows) {
        var rowHeight = 26;
        var gutter = 96;
        var trackWidth = 250;
        var countWidth = 60;
        var width = gutter + trackWidth + countWidth;
        var height = rows.length * rowHeight + 8;

        var svg = document.createElementNS(SVG_NS, "svg");
        svg.setAttribute("viewBox", "0 0 " + width + " " + height);
        svg.setAttribute("width", "100%");
        svg.setAttribute("height", height);
        svg.setAttribute("role", "img");

        rows.forEach(function (row, index) {
            var y = index * rowHeight + 8;

            var label = document.createElementNS(SVG_NS, "text");
            label.setAttribute("x", "0");
            label.setAttribute("y", y + 10);
            label.setAttribute("class", "svg-label");
            label.textContent = row.label;
            svg.appendChild(label);

            var track = document.createElementNS(SVG_NS, "rect");
            track.setAttribute("x", gutter);
            track.setAttribute("y", y);
            track.setAttribute("width", trackWidth);
            track.setAttribute("height", 12);
            track.setAttribute("rx", 6);
            track.setAttribute("class", "svg-track");
            svg.appendChild(track);

            if (row.value > 0) {
                var fill = document.createElementNS(SVG_NS, "rect");
                fill.setAttribute("x", gutter);
                fill.setAttribute("y", y);
                // Keep a sliver visible so zero-vs-tiny values stay readable.
                fill.setAttribute("width",
                    Math.max(2, Math.round(row.ratio * trackWidth)));
                fill.setAttribute("height", 12);
                fill.setAttribute("rx", 6);
                fill.setAttribute("fill", row.color);
                svg.appendChild(fill);
            }

            var count = document.createElementNS(SVG_NS, "text");
            count.setAttribute("x", gutter + trackWidth + 8);
            count.setAttribute("y", y + 10);
            count.setAttribute("class", "svg-count");
            count.textContent = String(row.value);
            svg.appendChild(count);
        });

        return svg;
    }

    // rows: [{label, value, color}]; total > 0 guaranteed.
    function withRatios(rows, total) {
        return rows.map(function (row) {
            return {
                label: row.label,
                value: row.value,
                color: row.color,
                ratio: row.value / total
            };
        });
    }

    function renderSeverityChart(container, tally, caption) {
        if (!container) {
            return;
        }
        clear(container);

        if (caption) {
            container.appendChild(el("p", "chart-title", caption));
        }

        var total = tally.HIGH + tally.MEDIUM + tally.LOW;
        if (!total) {
            container.appendChild(el("div", "hint",
                "No analysis data yet. Run an analysis to see real values."));
            return;
        }

        var svg = buildBarSvg(withRatios([
            { label: "HIGH", value: tally.HIGH, color: CHART_COLORS.HIGH },
            { label: "MEDIUM", value: tally.MEDIUM,
                color: CHART_COLORS.MEDIUM },
            { label: "LOW", value: tally.LOW, color: CHART_COLORS.LOW }
        ], total));
        container.appendChild(svg);

        container.appendChild(el("p", "hint",
            "Total real events counted: " + total + " (this page session " +
            "only; nothing is stored)."));
    }

    function renderCategoryChart(container, tally, caption) {
        if (!container) {
            return;
        }
        clear(container);

        if (caption) {
            container.appendChild(el("p", "chart-title", caption));
        }

        var keys = Object.keys(tally).filter(function (key) {
            return tally[key] > 0;
        }).sort(function (a, b) {
            return tally[b] - tally[a];
        });

        if (!keys.length) {
            container.appendChild(el("div", "hint",
                "No threat categories found yet. This is empty until real " +
                "analysis results exist — nothing is pre-filled."));
            return;
        }

        var total = keys.reduce(function (sum, key) {
            return sum + tally[key];
        }, 0);

        var svg = buildBarSvg(withRatios(keys.map(function (key) {
            return {
                label: key, value: tally[key],
                color: CHART_COLORS.category
            };
        }), total));
        container.appendChild(svg);
    }

    /* --------------------------------------------------- Threat Analytics */

    function renderAnalytics() {
        renderSeverityChart($("analytics-severity"), riskTally(),
            "Severity distribution");
        renderCategoryChart($("analytics-categories"), categoryTally(),
            "Threat categories");
    }

    /* -------------------------------------------------- Event Monitoring */

    function renderTimeline() {
        var mount = $("event-timeline");
        if (!mount) {
            return;
        }
        clear(mount);

        var events = sessionEvents();
        if (!events.length) {
            mount.appendChild(el("div", "empty-state",
                "No events yet. Analyze a log or upload a batch file; the " +
                "timeline lists only real results from this page session."));
            return;
        }

        var ul = el("ul", "timeline");
        events.forEach(function (event) {
            var li = el("li");
            if (event.risk) {
                li.setAttribute("data-risk", event.risk);
            }
            li.appendChild(el("div", "timeline-title", event.title));

            var badgeRow = el("div", "timeline-meta", event.source +
                " · " + event.detail);
            li.appendChild(badgeRow);
            ul.appendChild(li);
        });
        mount.appendChild(ul);
    }

    /* ------------------------------------------------------ public hook */

    window.CyberGuardUI = {
        addBatchReport: function (report) {
            if (report && report.available !== false) {
                store.batchReports.push(report);
                renderOverview();
                renderAnalytics();
                renderTimeline();
            }
        },
        navigate: activatePage
    };

    /* -------------------------------------------------------- Settings */

    function renderSettings(state) {
        var locationText = window.location.host || "unknown";

        setText("set-binding", "http://" + locationText + " (loopback only)");
        setText("set-mode", "Browser (desktop shell arrives in Stage 3)");
        setText("set-persistence",
            "No conversations, analyses or files are stored; a page reload " +
            "clears the session");
        setText("set-llm",
            "Chosen per request; default is the deterministic provider " +
            "(shown honestly beside every reply)");
        setText("set-batch",
            state.batch_limit
                ? "First " + state.batch_limit +
                    " non-blank lines per file (server-reported, " +
                    "truncation is always surfaced)"
                : "Server-enforced cap; every response reports truncation");
        setText("set-approval",
            "Preview and separate approval required for every privileged " +
            "action; elevation disabled by default");
        setText("set-telemetry",
            "None. The application performs no external calls except the " +
            "optional localhost Ollama server, which stays off unless " +
            "explicitly configured");
    }

    /* ------------------------------------------------------------ boot */

    document.addEventListener("DOMContentLoaded", function () {
        serverState = readServerState();

        wireNavigation();
        activatePage("overview", false);

        renderOverview();
        renderAnalytics();
        renderTimeline();
        renderSettings(serverState);

        if (serverState.form_error) {
            var alertBox = $("log-analysis-alert");
            if (alertBox) {
                alertBox.textContent = serverState.form_error;
            }
        }
    });
})();
