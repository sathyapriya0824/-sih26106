const API_BASE = window.location.origin;

// =====================================================
// BACKEND LOGIN + ROLE MANAGEMENT
// =====================================================

const loginScreen = document.getElementById("loginScreen");
const appShell = document.getElementById("appShell");
const loginForm = document.getElementById("loginForm");
const loginError = document.getElementById("loginError");

let currentUser = null;


// ---------- Show Dashboard ----------

function showDashboard(user) {

  currentUser = user;

  loginScreen.hidden = true;
  appShell.hidden = false;

  const historySection =
    document.querySelector(".history-panel");

  const reportButton =
    document.getElementById("downloadReport");


  // Normal user
  if (user.role === "user") {

    if (historySection) {
      historySection.hidden = true;
    }

    if (reportButton) {
      reportButton.hidden = true;
    }

  }

  // Analyst / Investigator / Admin
  else {

    if (historySection) {
      historySection.hidden = false;
    }

    if (reportButton) {
      reportButton.hidden = false;
    }

  }
}


// ---------- Show Login ----------

function showLogin() {

  loginScreen.hidden = false;
  appShell.hidden = true;

  currentUser = null;
}


// =====================================================
// LOGIN
// =====================================================

window.doLogin = async function () {

  const username =
    document.getElementById("loginUsername").value.trim();

  const password =
    document.getElementById("loginPassword").value;

  const selectedRole =
    document.getElementById("loginRole").value;


  loginError.textContent = "";


  // Check all fields

  if (!username || !password || !selectedRole) {

    loginError.textContent =
      "Please enter username, password and select your role.";

    return false;
  }


  try {

    const response = await fetch(
      `${API_BASE}/api/login`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json"
        },

        credentials: "include",

        body: JSON.stringify({
          username: username,
          password: password,
          role: selectedRole
        })
      }
    );


    const data = await response.json();


    // Invalid login

    if (!response.ok) {

      loginError.textContent =
        data.error || "Invalid username or password.";

      return false;
    }


    // Check selected role with backend role

    if (data.role !== selectedRole) {

      loginError.textContent =
        "Selected role does not match this account.";

      // Logout incorrect session

      await fetch(
        `${API_BASE}/api/logout`,
        {
          method: "POST",
          credentials: "include"
        }
      );

      return false;
    }


    // Successful login

    loginError.textContent = "";

    showDashboard(data);

  }

  catch (error) {

    console.error("Login error:", error);

    loginError.textContent =
      "Cannot connect to backend. Make sure Flask server is running.";

  }

  return false;
};


// =====================================================
// CHECK EXISTING BACKEND SESSION
// =====================================================

async function checkSession() {

  try {

    const response = await fetch(
      `${API_BASE}/api/me`,
      {
        method: "GET",
        credentials: "include"
      }
    );


    if (response.ok) {

      const data =
        await response.json();

      showDashboard(data);

    }

    else {

      showLogin();

    }

  }

  catch (error) {

    console.error("Session check error:", error);

    showLogin();

  }
}


// Check login when page loads

checkSession();


// =====================================================
// DOM REFERENCES
// =====================================================

const el = (id) =>
  document.getElementById(id);

const analyzeBtn =
  el("analyzeBtn");

const statusLine =
  el("statusLine");

const fileInput =
  el("fileInput");

const dropzone =
  el("dropzone");

const rawText =
  el("rawText");

const historyList =
  el("historyList");


let selectedFile = null;

let mapInstance = null;

let currentAnalysis = null;


// =====================================================
// SAMPLE LOADING
// =====================================================

document
  .querySelectorAll(".chip[data-sample]")
  .forEach((btn) => {

    btn.addEventListener("click", async () => {

      const sample =
        btn.dataset.sample;

      const path =
        sample === "phishing"
          ? "SAMPLE_PHISHING_EML"
          : "SAMPLE_LEGIT_EML";


      rawText.value =
        window[path];

      selectedFile = null;


      el("dropzoneLabel").textContent =
        "Drop .eml file or click to browse";


      setStatus(
        "Sample loaded. Click 'Run forensic analysis'."
      );

    });

  });


// =====================================================
// UPLOAD HANDLING
// =====================================================

dropzone.addEventListener(
  "click",
  () => fileInput.click()
);


fileInput.addEventListener(
  "change",
  () => {

    if (fileInput.files.length) {

      selectedFile =
        fileInput.files[0];


      el("dropzoneLabel").textContent =
        selectedFile.name;


      rawText.value = "";

    }

  }
);


// Drag over

["dragover", "dragenter"].forEach(
  (evt) => {

    dropzone.addEventListener(
      evt,
      (e) => {

        e.preventDefault();

        dropzone.classList.add("drag");

      }
    );

  }
);


// Drag leave / drop

["dragleave", "drop"].forEach(
  (evt) => {

    dropzone.addEventListener(
      evt,
      (e) => {

        e.preventDefault();

        dropzone.classList.remove("drag");

      }
    );

  }
);


// Drop file

dropzone.addEventListener(
  "drop",
  (e) => {

    const f =
      e.dataTransfer.files[0];


    if (f) {

      selectedFile = f;

      el("dropzoneLabel").textContent =
        f.name;

      rawText.value = "";

    }

  }
);


// =====================================================
// STATUS
// =====================================================

function setStatus(
  msg,
  isError = false
) {

  statusLine.textContent =
    msg;

  statusLine.className =
    "status-line" +
    (isError ? " error" : "");

}


// =====================================================
// ANALYZE
// =====================================================

analyzeBtn.addEventListener(
  "click",
  async () => {

    if (
      !selectedFile &&
      !rawText.value.trim()
    ) {

      setStatus(
        "Please upload a .eml file or paste raw email source first.",
        true
      );

      return;
    }


    analyzeBtn.disabled = true;


    setStatus(
      "Running forensic analysis — parsing headers, geolocating hops, scoring risk..."
    );


    try {

      let resp;


      // File upload

      if (selectedFile) {

        const fd =
          new FormData();

        fd.append(
          "file",
          selectedFile
        );


        resp =
          await fetch(
            `${API_BASE}/api/analyze`,
            {
              method: "POST",
              body: fd,
              credentials: "include"
            }
          );

      }


      // Raw email text

      else {

        resp =
          await fetch(
            `${API_BASE}/api/analyze`,
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json"
              },

              credentials: "include",

              body: JSON.stringify({
                raw_text:
                  rawText.value
              }),

            }
          );

      }


      const data =
        await resp.json();


      if (!resp.ok) {

        throw new Error(
          data.error ||
          "Analysis failed"
        );

      }


      currentAnalysis =
        data;


      renderAnalysis(data);

      prependHistory(data);


      setStatus(
        "Analysis complete."
      );

    }

    catch (err) {

      setStatus(
        err.message,
        true
      );

    }

    finally {

      analyzeBtn.disabled =
        false;

    }

  }
);


// =====================================================
// HISTORY
// =====================================================

function prependHistory(data) {

  if (
    historyList.querySelector(
      ".empty-note"
    )
  ) {

    historyList.innerHTML = "";

  }


  const item =
    document.createElement("div");


  item.className =
    "history-item";


  item.innerHTML = `
    <div class="h-top">

      <span class="h-subject">
        ${escapeHtml(
          data.summary.subject ||
          "(no subject)"
        )}
      </span>

      <span
        class="h-score"
        style="color:${riskColor(
          data.threat.risk_level
        )}"
      >
        ${data.threat.score}
      </span>

    </div>

    <div class="h-sender">
      ${escapeHtml(
        data.summary.from ||
        "unknown sender"
      )}
    </div>
  `;


  item.addEventListener(
    "click",
    () => renderAnalysis(data)
  );


  historyList.prepend(item);

}


// =====================================================
// RISK COLOR
// =====================================================

function riskColor(level) {

  return {

    Low: "#4ADE80",

    Medium: "#FFD166",

    High: "#FF9F45",

    Critical: "#FF5D5D"

  }[level] || "#7C8CA3";

}


// =====================================================
// TABS
// =====================================================

document
  .querySelectorAll(".tab")
  .forEach((tabBtn) => {

    tabBtn.addEventListener(
      "click",
      () => {

        document
          .querySelectorAll(".tab")
          .forEach(
            (t) =>
              t.classList.remove("active")
          );


        document
          .querySelectorAll(".tab-panel")
          .forEach(
            (p) =>
              (p.hidden = true)
          );


        tabBtn.classList.add("active");


        el(
          `tab-${tabBtn.dataset.tab}`
        ).hidden = false;


        if (
          tabBtn.dataset.tab === "geo" &&
          mapInstance
        ) {

          setTimeout(
            () =>
              mapInstance.invalidateSize(),
            50
          );

        }

      }
    );

  });


// =====================================================
// RENDER ANALYSIS
// =====================================================

function renderAnalysis(data) {

  el("emptyState").hidden =
    true;

  el("resultView").hidden =
    false;


  el("caseId").textContent =
    `CASE ${data.case_id || "—"}`;


  el("caseSubject").textContent =
    data.summary.subject ||
    "(no subject)";


  el("caseFrom").textContent =
    data.summary.from ||
    "—";


  el("caseTo").textContent =
    data.summary.to ||
    "—";


  el("caseDate").textContent =
    data.summary.date ||
    "—";


  const score =
    data.threat.score;


  const circumference =
    327;


  const offset =
    circumference -
    (score / 100) *
      circumference;


  const gaugeFill =
    el("gaugeFill");


  gaugeFill.style.strokeDashoffset =
    offset;


  gaugeFill.style.stroke =
    riskColor(
      data.threat.risk_level
    );


  el("gaugeNum").textContent =
    score;


  const pill =
    el("riskPill");


  pill.textContent =
    data.threat.risk_level.toUpperCase();


  pill.className =
    "risk-pill " +
    data.threat.risk_level;


  renderAuth(
    data.authentication
  );


  renderLanguage(
    data.language_analysis
  );


  renderFindings(
    data.threat.findings
  );


  renderHops(
    data.hops
  );


  renderGeo(
    data.hops,
    data.origin_geolocation
  );


  renderLinks(
    data.links
  );


  renderAttachments(
    data.attachments
  );


  el("downloadReport").onclick =
    () => {

      window.open(
        `${API_BASE}/api/report/${data.case_id}`,
        "_blank"
      );

    };

}


// =====================================================
// AUTHENTICATION
// =====================================================

function renderAuth(auth) {

  const grid =
    el("authGrid");


  grid.innerHTML = "";


  Object.entries(auth)
    .forEach(
      ([mech, result]) => {

        const row =
          document.createElement(
            "div"
          );


        row.className =
          "auth-row";


        row.innerHTML = `
          <span class="auth-mech">
            ${mech}
          </span>

          <span class="auth-result ${result}">
            ${result}
          </span>
        `;


        grid.appendChild(row);

      }
    );

}


// =====================================================
// LANGUAGE RISK
// =====================================================

function renderLanguage(lang) {

  el("langBarFill").style.width =
    `${lang.language_risk_score}%`;


  el("langScore").textContent =
    `${lang.language_risk_score} / 100`;


  const chips =
    el("phraseChips");


  chips.innerHTML =
    lang.matched_phrases.length

      ? lang.matched_phrases
          .map(
            (p) =>
              `<span class="phrase-chip">
                ${escapeHtml(p)}
              </span>`
          )
          .join("")

      : `<span class="hint">
           No phishing-style phrases detected.
         </span>`;

}


// =====================================================
// FINDINGS
// =====================================================

function renderFindings(findings) {

  const list =
    el("findingsList");


  if (!findings.length) {

    list.innerHTML =
      `<div class="no-data">
        No risk indicators were triggered —
        message appears clean.
      </div>`;

    return;
  }


  list.innerHTML =
    findings
      .sort(
        (a, b) =>
          b.points - a.points
      )
      .map(
        (f) => `
          <div class="finding-row ${f.severity}">

            <div class="finding-pts">
              +${f.points}
            </div>

            <div class="finding-label">
              ${escapeHtml(f.label)}
            </div>

          </div>
        `
      )
      .join("");

}


// =====================================================
// DELIVERY HOPS
// =====================================================

function renderHops(hops) {

  const timeline =
    el("hopTimeline");


  if (!hops.length) {

    timeline.innerHTML =
      `<div class="no-data">
        No Received headers found in this message.
      </div>`;

    return;
  }


  timeline.innerHTML =
    hops
      .map(
        (hop) => `
          <div class="hop-item">

            <div class="hop-dot-col">

              <div class="hop-dot"></div>

              <div class="hop-line"></div>

            </div>

            <div class="hop-body">

              <div class="hop-host">

                Hop ${hop.hop_index}:
                ${escapeHtml(
                  hop.from_host ||
                  "unknown host"
                )}

                →

                ${escapeHtml(
                  hop.by_host ||
                  "unknown host"
                )}

              </div>


              ${
                hop.public_ips.length

                  ? `<span class="hop-ip">
                       ${hop.public_ips.join(", ")}
                     </span>`

                  : `<span class="hint">
                       no public IP in this hop
                     </span>`
              }


              <div class="hop-raw">
                ${escapeHtml(
                  hop.raw
                )}
              </div>

            </div>

          </div>
        `
      )
      .join("");

}


// =====================================================
// GEOLOCATION
// =====================================================

function renderGeo(
  hops,
  originGeo
) {

  if (mapInstance) {

    mapInstance.remove();

    mapInstance = null;

  }


  mapInstance =
    L.map(
      "map",
      {
        zoomControl: true,
        attributionControl: false
      }
    )
    .setView(
      [20, 0],
      2
    );


  L.tileLayer(
    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {
      subdomains:
        "abcd",

      maxZoom:
        19,

    }
  ).addTo(
    mapInstance
  );


  const points = [];


  const geoTable =
    el("geoTable");


  geoTable.innerHTML = "";


  hops.forEach(
    (hop) => {

      (hop.geolocation || [])
        .forEach(
          (g) => {

            if (
              g.status ===
              "success"
            ) {

              points.push([
                g.lat,
                g.lon
              ]);


              L.circleMarker(
                [
                  g.lat,
                  g.lon
                ],
                {
                  radius: 7,

                  color:
                    "#35D1C0",

                  fillColor:
                    "#35D1C0",

                  fillOpacity:
                    0.7

                }
              )

                .bindPopup(
                  `<b>${g.ip}</b><br>
                   ${g.city || ""},
                   ${g.country || ""}<br>
                   ${g.isp || ""}`
                )

                .addTo(
                  mapInstance
                );

            }


            const row =
              document.createElement(
                "div"
              );


            row.className =
              "geo-row";


            if (
              g.status ===
              "success"
            ) {

              row.innerHTML =
                `<span class="geo-ip">
                   ${g.ip}
                 </span>

                 <span class="geo-loc">
                   ${escapeHtml(
                     g.city || ""
                   )},
                   ${escapeHtml(
                     g.country || ""
                   )}
                   ·
                   ${escapeHtml(
                     g.isp || ""
                   )}
                 </span>`;

            }

            else if (
              g.status ===
              "private"
            ) {

              row.innerHTML =
                `<span class="geo-ip">
                   ${g.ip}
                 </span>

                 <span class="geo-loc">
                   Internal /
                   private network
                 </span>`;

            }

            else {

              row.innerHTML =
                `<span class="geo-ip">
                   ${g.ip}
                 </span>

                 <span class="geo-loc">
                   Location unresolved
                 </span>`;

            }


            geoTable.appendChild(
              row
            );

          }
        );

    }
  );


  if (points.length) {

    mapInstance.fitBounds(
      points,
      {
        padding:
          [30, 30],

        maxZoom:
          6

      }
    );

  }


  if (
    !geoTable.children.length
  ) {

    geoTable.innerHTML =
      `<div class="no-data">
        No public IP addresses were found to geolocate.
      </div>`;

  }

}


// =====================================================
// SUSPICIOUS LINKS
// =====================================================

function renderLinks(links) {

  const list =
    el("linksList");


  if (!links.length) {

    list.innerHTML =
      `<div class="no-data">
        No suspicious links detected in the message body.
      </div>`;

    return;
  }


  list.innerHTML =
    links
      .map(
        (l) => `
          <div class="link-item">

            <div class="link-url">
              ${escapeHtml(l.url)}
            </div>

            <div class="link-issues">

              ${l.issues
                .map(
                  (i) =>
                    `<div>
                      ⚠ ${escapeHtml(i)}
                     </div>`
                )
                .join("")}

            </div>

          </div>
        `
      )
      .join("");

}


// =====================================================
// ATTACHMENTS
// =====================================================

function renderAttachments(
  attachments
) {

  const list =
    el("attachmentsList");


  if (!attachments.length) {

    list.innerHTML =
      `<div class="no-data">
        No attachments found.
      </div>`;

    return;
  }


  list.innerHTML =
    attachments
      .map(
        (a) => `

          <div class="attach-item">

            <div>

              <div class="attach-name">
                ${escapeHtml(
                  a.filename
                )}
              </div>

              <div class="attach-meta">

                ${escapeHtml(
                  a.content_type
                )}

                ·

                ${a.size_bytes}
                bytes

                <br>

                SHA-256:

                ${
                  a.sha256
                    ? a.sha256.slice(
                        0,
                        32
                      ) + "..."
                    : "n/a"
                }

              </div>

            </div>


            <div
              class="attach-flag ${
                a.suspicious_extension
                  ? "danger"
                  : "ok"
              }"
            >

              ${
                a.suspicious_extension
                  ? "HIGH RISK"
                  : "no known risk"
              }

            </div>

          </div>

        `
      )
      .join("");

}


// =====================================================
// ESCAPE HTML
// =====================================================

function escapeHtml(str) {

  if (
    str === null ||
    str === undefined
  ) {

    return "";

  }


  return String(str)

    .replace(
      /&/g,
      "&amp;"
    )

    .replace(
      /</g,
      "&lt;"
    )

    .replace(
      />/g,
      "&gt;"
    )

    .replace(
      /"/g,
      "&quot;"
    );

}