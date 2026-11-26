let lastTrafficId = 0;
let livePaused = false;


/* ========================================
   INITIALIZE
======================================== */

document.addEventListener("DOMContentLoaded", function () {

    initializeLastTrafficId();

    bindFilters();
    bindPauseButton();
    bindModalButtons();

    applyFilters();

    setInterval(loadLiveTraffic, 2000);
});


function initializeLastTrafficId() {

    document
        .querySelectorAll("#trafficTableBody tr[data-id]")
        .forEach(row => {

            const id = parseInt(row.dataset.id || "0");

            if (id > lastTrafficId) {
                lastTrafficId = id;
            }

        });
}


/* ========================================
   SECURITY
======================================== */

function escapeHtml(value) {

    const div = document.createElement("div");

    div.textContent =
        value === null || value === undefined
            ? ""
            : String(value);

    return div.innerHTML;
}


/* ========================================
   BADGES
======================================== */

function statusBadge(status) {

    if (status === "Normal") {
        return `<span class="badge-normal">Normal</span>`;
    }
      if (status === "Suspicious") {

        return `
            <span class="badge-warning">
                Suspicious
            </span>
        `;
    }
    if (status === "Intrusion") {
        return `<span class="badge-danger">Intrusion</span>`;
    }

    return `
        <span class="badge-warning">
            ${escapeHtml(status || "Pending")}
        </span>
    `;
}


function methodBadge(method) {

    const safeMethod =
        escapeHtml(method || "UNKNOWN");

    const cssMethod =
        String(method || "unknown").toLowerCase();

    return `
        <span class="method-badge method-${cssMethod}">
            ${safeMethod}
        </span>
    `;
}


function riskBadge(risk) {

    const safeRisk =
        escapeHtml(risk || "Low");

    const cssRisk =
        String(risk || "Low").toLowerCase();

    return `
        <span class="risk-badge risk-${cssRisk}">
            ${safeRisk}
        </span>
    `;
}


/* ========================================
   CREATE ROW
======================================== */

function createTrafficRow(log) {

    const row = document.createElement("tr");

    row.className =
        "traffic-row traffic-row-new";

    row.dataset.id = log.id;
    row.dataset.ip = log.source_ip || "";
    row.dataset.method = log.method || "";
    row.dataset.path = log.path || "";
    row.dataset.url = log.url || "";
    row.dataset.query = log.query_string || "";
    row.dataset.userAgent = log.user_agent || "";
    row.dataset.contentLength = log.content_length || 0;
    row.dataset.status = log.status || "Pending";
    row.dataset.attack = log.attack_type || "Unknown";
    row.dataset.risk = log.risk_level || "Low";
    row.dataset.model =
    log.model_name || "";

row.dataset.confidence =
    log.confidence !== null &&
    log.confidence !== undefined
        ? log.confidence
        : 0;
    row.dataset.created = log.created_at || "";

    row.innerHTML = `

        <td class="traffic-time">
            ${escapeHtml(log.created_at)}
        </td>

        <td>
            <span class="ip-address">
                ${escapeHtml(log.source_ip)}
            </span>
        </td>

        <td>
            ${methodBadge(log.method)}
        </td>

        <td>
            <div class="request-path"
                 title="${escapeHtml(log.path)}">
                ${escapeHtml(log.path)}
            </div>
        </td>

        <td>
            ${statusBadge(log.status)}
        </td>

        <td>
            ${escapeHtml(log.attack_type)}
        </td>

        <td>
            ${riskBadge(log.risk_level)}
        </td>
<td>
    ${escapeHtml(log.model_name || "-")}
</td>

<td>
    ${
        log.confidence !== null &&
        log.confidence !== undefined
            ? escapeHtml(
                Number(log.confidence).toFixed(4)
              )
            : "-"
    }
</td>
        <td>

            <button type="button"
                    class="btn btn-sm btn-outline-info view-request">

                <i class="bi bi-eye"></i>

            </button>

        </td>
    `;

    return row;
}


/* ========================================
   LIVE API
======================================== */

async function loadLiveTraffic() {

    if (livePaused) {
        return;
    }

    try {

        const response = await fetch(
            `/api/live-traffic?last_id=${lastTrafficId}`,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("Server error");
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(data.message);
        }

        updateStatistics(data.statistics);

        const tableBody =
            document.getElementById("trafficTableBody");

        data.logs.forEach(log => {

            const exists =
                document.querySelector(
                    `tr[data-id="${log.id}"]`
                );

            if (exists) {
                return;
            }

            const row =
                createTrafficRow(log);

            tableBody.prepend(row);

            if (log.id > lastTrafficId) {
                lastTrafficId = log.id;
            }

        });

        bindModalButtons();

        trimRows();
        applyFilters();

        setConnectionStatus(true);

    }

    catch (error) {

        console.error(
            "Live traffic error:",
            error
        );

        setConnectionStatus(false);
    }
}


/* ========================================
   STATISTICS
======================================== */

function updateStatistics(stats) {

    const totalElement =
        document.getElementById(
            "totalTraffic"
        );

    const normalElement =
        document.getElementById(
            "normalTraffic"
        );

    const suspiciousElement =
        document.getElementById(
            "suspiciousTraffic"
        );

    const intrusionElement =
        document.getElementById(
            "intrusionTraffic"
        );

    const criticalElement =
        document.getElementById(
            "criticalTraffic"
        );


    if (totalElement) {
        totalElement.textContent =
            stats.total || 0;
    }

    if (normalElement) {
        normalElement.textContent =
            stats.normal || 0;
    }

    if (suspiciousElement) {
        suspiciousElement.textContent =
            stats.suspicious || 0;
    }

    if (intrusionElement) {
        intrusionElement.textContent =
            stats.intrusion || 0;
    }

    if (criticalElement) {
        criticalElement.textContent =
            stats.critical || 0;
    }
}


/* ========================================
   CONNECTION
======================================== */

function setConnectionStatus(connected) {

    const element =
        document.getElementById("connectionStatus");

    if (!element) return;

    if (connected) {

        element.innerHTML = `
            <span class="status-dot"></span>
            Connected
        `;

    } else {

        element.innerHTML = `
            <i class="bi bi-wifi-off me-1"></i>
            Connection Lost
        `;
    }
}


/* ========================================
   FILTERS
======================================== */

function bindFilters() {

    const filterIds = [
        "searchInput",
        "methodFilter",
        "statusFilter",
        "attackFilter",
        "riskFilter",
        "rowLimit"
    ];

    filterIds.forEach(id => {

        const element =
            document.getElementById(id);

        if (!element) return;

        element.addEventListener(
            id === "searchInput"
                ? "input"
                : "change",
            applyFilters
        );
    });


    document
        .getElementById("clearFilters")
        .addEventListener("click", function () {

            document.getElementById(
                "searchInput"
            ).value = "";

            document.getElementById(
                "methodFilter"
            ).value = "";

            document.getElementById(
                "statusFilter"
            ).value = "";

            document.getElementById(
                "attackFilter"
            ).value = "";

            document.getElementById(
                "riskFilter"
            ).value = "";

            applyFilters();
        });
}


function applyFilters() {

    const search =
        document.getElementById(
            "searchInput"
        ).value.toLowerCase().trim();

    const method =
        document.getElementById(
            "methodFilter"
        ).value;

    const status =
        document.getElementById(
            "statusFilter"
        ).value;

    const attack =
        document.getElementById(
            "attackFilter"
        ).value;

    const risk =
        document.getElementById(
            "riskFilter"
        ).value;

    const limit =
        parseInt(
            document.getElementById(
                "rowLimit"
            ).value
        );


    const rows =
        Array.from(
            document.querySelectorAll(
                "#trafficTableBody .traffic-row"
            )
        );


    let visible = 0;


    rows.forEach(row => {

        const searchableText = [
            row.dataset.ip,
            row.dataset.method,
            row.dataset.path,
            row.dataset.url,
            row.dataset.query,
            row.dataset.attack,
            row.dataset.status,
            row.dataset.risk,
            row.dataset.model
        ]
            .join(" ")
            .toLowerCase();


        const matchesSearch =
            !search ||
            searchableText.includes(search);

        const matchesMethod =
            !method ||
            row.dataset.method === method;

        const matchesStatus =
            !status ||
            row.dataset.status === status;

        const matchesAttack =
            !attack ||
            row.dataset.attack === attack;

        const matchesRisk =
            !risk ||
            row.dataset.risk === risk;


        const matches =
            matchesSearch &&
            matchesMethod &&
            matchesStatus &&
            matchesAttack &&
            matchesRisk;


        if (matches && visible < limit) {

            row.style.display = "";

            visible++;

        } else {

            row.style.display = "none";
        }
    });


    document.getElementById(
        "visibleCount"
    ).textContent = visible;


    document.getElementById(
        "noResults"
    ).style.display =
        visible === 0
            ? "block"
            : "none";
}


/* ========================================
   ROW LIMIT
======================================== */

function trimRows() {

    const rows =
        document.querySelectorAll(
            "#trafficTableBody .traffic-row"
        );

    /*
       Keep a reasonable number in the browser.
       Historical records remain in SQLite.
    */

    const maxRows = 200;

    if (rows.length > maxRows) {

        for (
            let i = maxRows;
            i < rows.length;
            i++
        ) {
            rows[i].remove();
        }
    }
}


/* ========================================
   PAUSE / RESUME
======================================== */

function bindPauseButton() {

    const button =
        document.getElementById("pauseButton");

    button.addEventListener(
        "click",
        function () {

            livePaused = !livePaused;

            if (livePaused) {

                button.innerHTML = `
                    <i class="bi bi-play-fill"></i>
                    Resume
                `;

                button.classList.remove(
                    "btn-outline-warning"
                );

                button.classList.add(
                    "btn-outline-success"
                );

            } else {

                button.innerHTML = `
                    <i class="bi bi-pause-fill"></i>
                    Pause
                `;

                button.classList.remove(
                    "btn-outline-success"
                );

                button.classList.add(
                    "btn-outline-warning"
                );

                /*
                    Immediately retrieve traffic
                    accumulated while paused.
                */
                loadLiveTraffic();
            }

        }
    );
}


/* ========================================
   DETAILS MODAL
======================================== */

function bindModalButtons() {

    document
        .querySelectorAll(".view-request")
        .forEach(button => {

            if (button.dataset.bound === "true") {
                return;
            }

            button.dataset.bound = "true";

            button.addEventListener(
                "click",
                function () {

                    const row =
                        this.closest(".traffic-row");

                    showRequestDetails(row);
                }
            );
        });
}


function showRequestDetails(row) {

    setDetail("detailId", row.dataset.id);
    setDetail("detailTime", row.dataset.created);
    setDetail("detailIp", row.dataset.ip);
    setDetail("detailMethod", row.dataset.method);

    setDetail(
        "detailUrl",
        row.dataset.url || "-"
    );

    setDetail(
        "detailPath",
        row.dataset.path || "-"
    );

    setDetail(
        "detailQuery",
        row.dataset.query || "No query string"
    );

    setDetail(
        "detailUserAgent",
        row.dataset.userAgent || "-"
    );

    setDetail(
        "detailContentLength",
        row.dataset.contentLength || "0"
    );

    setDetail(
        "detailStatus",
        row.dataset.status
    );

    setDetail(
        "detailAttack",
        row.dataset.attack
    );

    setDetail(
        "detailRisk",
        row.dataset.risk
    );
setDetail(
        "detailModel",
        row.dataset.model
    );
setDetail(
    "detailConfidence",
    row.dataset.confidence
        ? Number(
            row.dataset.confidence
          ).toFixed(4)
        : "-"
);
    const modalElement =
        document.getElementById(
            "requestDetailsModal"
        );

    const modal =
        bootstrap.Modal.getOrCreateInstance(
            modalElement
        );

    modal.show();
}


function setDetail(id, value) {

    document.getElementById(
        id
    ).textContent = value || "-";
}