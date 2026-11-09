/*
 * CyberGuard AI - batch log-file analysis (extracted from the legacy
 * template in Stage 2; behaviour identical to the released code, plus one
 * integration hook: finished reports are handed to the UI state layer
 * (window.CyberGuardUI) so Overview / Analytics / Event Monitoring pages
 * reflect the same real data. No report content is fabricated here.
 */
(function () {
    "use strict";

    var form = document.getElementById("batch-form");
    if (!form) {
        return;
    }

    var input = document.getElementById("batch-file");
    var button = document.getElementById("batch-send");
    var status = document.getElementById("batch-status");
    var results = document.getElementById("batch-results");

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

    function show(value) {
        return (value === null || value === undefined || value === "") ? "—" : value;
    }

    function renderTable(caption, headers, rows, options) {
        var snippetColumn = (options && options.snippetColumn) || -1;

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
            var rowNode = el("tr");
            row.forEach(function (cell, index) {
                rowNode.appendChild(
                    el("td", index === snippetColumn ? "batch-snippet" : null,
                       show(cell))
                );
            });
            body.appendChild(rowNode);
        });
        table.appendChild(body);

        return table;
    }

    function describe(report) {
        var parts = [];
        parts.push(show(report.filename) + ": " +
            report.lines_analyzed + " of " + report.lines_total +
            " lines analysed");
        parts.push(report.suspicious + " suspicious");
        parts.push(report.benign + " benign");
        parts.push((report.duration_ms / 1000).toFixed(1) + " s");

        if (report.duplicates_collapsed) {
            parts.push(report.duplicates_collapsed + " duplicate lines collapsed");
        }
        if (report.truncated) {
            parts.push("truncated at " + report.limit + " lines");
        }
        if (report.error_count) {
            parts.push(report.error_count + " line(s) failed to analyse");
        }
        return parts.join(" · ");
    }

    function render(report) {
        results.textContent = "";

        if (report.available === false) {
            status.textContent = "Batch analysis failed: " +
                (report.error || "unknown error");
            return;
        }

        var meta = el("p", "batch-meta", describe(report));
        results.appendChild(meta);

        if (report.truncated) {
            results.appendChild(el("p", "hint",
                "Only the first " + report.limit + " non-blank lines were " +
                "analysed. Split the file or raise " +
                "CYBERGUARD_BATCH_MAX_LINES to cover more."));
        }

        if (report.threat_types.length) {
            results.appendChild(renderTable(
                "Threat types",
                ["Threat type", "Lines"],
                report.threat_types.map(function (row) {
                    return [row.threat_type, row.count];
                })
            ));
        }

        if (report.risks.length) {
            results.appendChild(renderTable(
                "Risk levels",
                ["Risk", "Lines"],
                report.risks.map(function (row) {
                    return [row.risk, row.count];
                })
            ));
        }

        if (report.samples.length) {
            results.appendChild(renderTable(
                "Suspicious lines (first " + report.samples.length + ")",
                ["Line", "Threat", "Risk", "Source IP", "User", "Attempts",
                 "Log line"],
                report.samples.map(function (row) {
                    return [row.line_number, row.threat_type, row.risk,
                            row.source_ip, row.username, row.attempts,
                            row.snippet];
                }),
                { snippetColumn: 6 }
            ));

            if (report.samples_truncated) {
                results.appendChild(el("p", "hint",
                    "Showing the first " + report.samples.length +
                    " suspicious lines only."));
            }
        } else if (report.lines_analyzed) {
            results.appendChild(el("p", "hint",
                "No known threat pattern matched in this file."));
        }

        if (report.errors && report.errors.length) {
            results.appendChild(renderTable(
                "Lines that failed to analyse",
                ["Error", "Log line"],
                report.errors.map(function (row) {
                    return [row.error, row.line];
                }),
                { snippetColumn: 1 }
            ));
        }

        // Integration hook: feed the same real report to the app shell so
        // Timeline / Analytics / Overview stay consistent (no fake data).
        if (window.CyberGuardUI && window.CyberGuardUI.addBatchReport) {
            window.CyberGuardUI.addBatchReport(report);
        }

        if (report.error) {
            status.textContent = "Batch analysis failed: " + report.error;
        }
    }

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        var file = input.files && input.files[0];

        if (!file) {
            status.textContent = "Choose a log file first.";
            return;
        }

        var body = new FormData();
        body.append("file", file, file.name);

        button.disabled = true;
        status.textContent = "Analysing " + file.name + " locally...";
        results.textContent = "";

        fetch("/api/batch", { method: "POST", body: body })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (!response.ok) {
                        throw new Error(data.error || "Request failed.");
                    }
                    return data;
                });
            })
            .then(function (report) {
                status.textContent = "";
                render(report);
            })
            .catch(function (error) {
                status.textContent = "Error: " + error.message;
            })
            .finally(function () {
                button.disabled = false;
            });
    });
})();
