"use strict";
const $ = (id) => document.getElementById(id);
let config, current, busy = false;
function node(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}
function notice(message) { $("notice").textContent = message; $("notice").hidden = !message; }
function formatDate(date) { return new Date(date).toLocaleString([], {dateStyle: "medium", timeStyle: "short"}); }
async function api(path, options = {}) {
  const headers = {...options.headers};
  if (options.method && options.method !== "GET") headers["X-PacketPilot-Token"] = config.csrf;
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {...options, headers});
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Check the supplied details and try again.");
  return data;
}
async function loadConfig() {
  config = await api("/api/config");
  $("connection-label").textContent = config.api_ready ? "AI connected" : "Offline ready · API key not added";
  $("connection-dot").classList.toggle("green", config.api_ready);
}
async function refreshList() {
  const reviews = await api("/api/reviews");
  $("review-count").textContent = reviews.length;
  $("review-list").replaceChildren();
  if (!reviews.length) $("review-list").append(node("p", "Your reviews will appear here. Start with either sample capture.", "sidebar-empty"));
  for (const review of reviews) {
    const button = node("button", undefined, "review-item" + (current?.id === review.id ? " selected" : ""));
    button.append(node("strong", review.title), node("small", `${review.provider === "api" ? "AI conversation" : "Offline rules"} · ${formatDate(review.updated_at)}`));
    button.onclick = () => selectReview(review.id).catch(error => notice(error.message));
    $("review-list").append(button);
  }
}
async function openNew(sample = "port-check", upload = false) {
  await loadConfig();
  $("sample").value = sample;
  $("capture-file").value = "";
  $("provider").querySelector('[value="api"]').disabled = !config.api_ready;
  $("provider").value = config.api_ready ? "api" : "rules";
  $("provider-help").textContent = config.api_ready
    ? "Opening a review is offline. A model call is made only when you submit a question. API charges apply."
    : "You can review packet evidence now. Run the API-key setup inside Ubuntu to enable saved AI conversations.";
  $("dialog-error").hidden = true;
  $("new-dialog").showModal();
  if (upload) $("capture-file").focus();
}
function renderReview(review) {
  current = review;
  $("welcome").hidden = true;
  $("workspace").hidden = false;
  $("review-title").textContent = review.title;
  const evidence = review.evidence;
  $("review-meta").textContent = `${evidence.capture.packet_count} packets · ${evidence.decoder.version} · saved capture`;
  const findingLabels = {scan_like: "Port-check pattern", no_scan_pattern: "No port-check pattern", insufficient_evidence: "Incomplete evidence"};
  $("finding-badge").textContent = findingLabels[evidence.finding] || evidence.finding;
  $("finding-badge").classList.toggle("neutral", evidence.finding === "no_scan_pattern");
  $("mode-label").textContent = review.provider === "api" ? "AI assistant · saved history" : "Offline rules · no model";
  $("mode-help").textContent = review.provider === "api" ? "Same capture, saved conversation. Each question uses the configured hosted API." : "Fixed rule summaries only. Use an AI review for open-ended explanations.";
  $("send-question").textContent = review.provider === "api" ? "Ask PacketPilot ↑" : "Show rule summary ↑";
  $("export-review").href = `/api/reviews/${review.id}/export`;
  $("facts").replaceChildren();
  $("fact-count").textContent = `${evidence.facts.length} linked facts`;
  evidence.facts.forEach((fact, index) => {
    const card = node("section", undefined, "fact"); card.id = `fact-${index}`;
    card.append(node("div", `EVIDENCE ${index + 1}`, "fact-label"), node("p", fact.text), node("small", `Packets ${fact.packet_refs.join(", ")}`));
    $("facts").append(card);
  });
  $("capture-hash").textContent = `Capture SHA-256: ${evidence.capture.sha256}`;
  $("limitations-list").replaceChildren(...evidence.limitations.map(text => node("li", text)));
  $("preview-block").disabled = evidence.finding !== "scan_like";
  $("preview-block").title = evidence.finding === "scan_like" ? "Preview only; no firewall rule will be applied." : "A source-block preview needs a supported port-check finding.";
  $("preview-result").hidden = true;
  if (review.previews.length) renderPreview(review.previews.at(-1).result);
  $("turns").replaceChildren();
  if (!review.turns.length) {
    const empty = node("div", undefined, "empty-conversation");
    empty.append(node("strong", "The capture is ready."), node("p", review.provider === "api" ? "Ask a question to start. PacketPilot sends structured facts to the configured AI service—not the raw capture—and keeps the conversation with this review." : "The packet evidence is available alongside the conversation. Show the fixed-rule summary below, or start an AI review after adding your key."));
    $("turns").append(empty);
  }
  review.turns.forEach(renderTurn);
  $("turns").scrollTop = $("turns").scrollHeight;
}
function renderTurn(result) {
  const turn = node("article", undefined, "turn"), explanation = result.explanation, answer = explanation.answer;
  turn.append(node("p", result.question, "question-message"));
  const fallback = explanation.status === "fallback_after_api_failure";
  turn.append(node("div", fallback ? "API UNAVAILABLE · FIXED-RULE FALLBACK" : explanation.source === "api" ? "PACKETPILOT" : "FIXED RULES · NO MODEL RESPONSE", "answer-label" + (fallback ? " fallback" : "")));
  if (fallback) turn.append(node("p", explanation.api_error.message, "api-error"));
  turn.append(node("p", answer.summary, "answer-summary"));
  for (const [label, value] of [["Why", answer.why], ["What to check next", answer.next_step]]) turn.append(node("span", label, "answer-section-label"), node("p", value, "answer-paragraph"));
  const links = node("div", undefined, "answer-links");
  for (const id of answer.fact_ids) {
    const index = current.evidence.facts.findIndex(fact => fact.id === id);
    if (index < 0) continue;
    const button = node("button", `Evidence ${index + 1} ↗`, "evidence-link");
    button.onclick = () => { document.querySelectorAll(".fact").forEach(fact => fact.classList.remove("highlight")); const fact = $(`fact-${index}`); fact.classList.add("highlight"); fact.scrollIntoView({block: "nearest"}); };
    links.append(button);
  }
  turn.append(links);
  const usage = explanation.usage?.total_tokens ? ` · ${explanation.usage.total_tokens} tokens` : "";
  turn.append(node("div", `${formatDate(result.recorded_at)}${usage} · No network action executed`, "turn-meta"));
  $("turns").append(turn);
}
function renderPreview(result) {
  const target = $("preview-result"); target.replaceChildren(); target.hidden = false;
  target.append(node("strong", result.allowed_preview ? "Preview permitted · NOT EXECUTED" : "Preview rejected · NOT EXECUTED"), node("p", result.operator_note));
  for (const reason of result.reasons) target.append(node("p", reason));
  if (result.target) target.append(node("small", `Target: ${result.target} · 60 seconds`));
}
async function selectReview(id, replace = false) {
  if (busy) return;
  renderReview(await api(`/api/reviews/${encodeURIComponent(id)}`));
  const next = `#review=${id}`;
  if (location.hash !== next) history[replace ? "replaceState" : "pushState"]({}, "", next);
  await refreshList(); notice("");
}
$("new-review").onclick = () => openNew().catch(error => notice(error.message));
$("upload-start").onclick = () => openNew("port-check", true).catch(error => notice(error.message));
$("close-dialog").onclick = () => $("new-dialog").close();
document.querySelectorAll("[data-sample]").forEach(button => { button.onclick = () => openNew(button.dataset.sample).catch(error => notice(error.message)); });
document.querySelectorAll("[data-question]").forEach(button => { button.onclick = () => { $("question").value = button.dataset.question; $("question").focus(); }; });
$("sample").onchange = () => { $("capture-file").value = ""; };
$("new-form").onsubmit = async event => {
  event.preventDefault(); $("create-review").disabled = true; $("dialog-error").hidden = true;
  try {
    const file = $("capture-file").files[0]; let review;
    if (file) { if (file.size > config.max_upload_bytes) throw new Error("The upload limit is 8 MiB."); const data = new FormData(); data.append("file", file); data.append("provider", $("provider").value); review = await api("/api/reviews/upload", {method: "POST", body: data}); }
    else review = await api("/api/reviews", {method: "POST", body: JSON.stringify({sample: $("sample").value, provider: $("provider").value})});
    $("new-dialog").close(); await selectReview(review.id); $("question").focus();
  } catch (error) { $("dialog-error").textContent = error.message; $("dialog-error").hidden = false; }
  finally { $("create-review").disabled = false; }
};
$("question-form").onsubmit = async event => {
  event.preventDefault(); const question = $("question").value.trim(); if (!question || busy || !current) return;
  busy = true; $("send-question").disabled = true; $("new-review").disabled = true; $("working").hidden = false; notice("");
  try { await api(`/api/reviews/${current.id}/questions`, {method: "POST", body: JSON.stringify({question, request_id: crypto.randomUUID()})}); $("question").value = ""; renderReview(await api(`/api/reviews/${current.id}`)); await refreshList(); }
  catch (error) { notice(error.message); }
  finally { busy = false; $("send-question").disabled = false; $("new-review").disabled = false; $("working").hidden = true; $("question").focus(); }
};
$("question").onkeydown = event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); $("question-form").requestSubmit(); } };
$("preview-block").onclick = async () => { try { renderPreview(await api(`/api/reviews/${current.id}/preview`, {method: "POST", body: JSON.stringify({action: "block_source"})})); } catch (error) { notice(error.message); } };
window.onpopstate = () => { const id = new URLSearchParams(location.hash.slice(1)).get("review"); if (id) selectReview(id, true).catch(error => notice(error.message)); };
(async () => { try { await loadConfig(); await refreshList(); const id = new URLSearchParams(location.hash.slice(1)).get("review"); if (id) await selectReview(id, true); } catch (error) { notice(error.message); } })();
