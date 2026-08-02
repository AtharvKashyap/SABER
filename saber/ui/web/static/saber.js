// Mission launch. The run endpoint takes a JSON body, so the form is serialized
// here rather than posted form-encoded, and the operator is sent straight to the
// mission page so they can watch the loop from its first decision.
(function () {
  "use strict";

  var form = document.getElementById("mission-start-form");
  if (!form) {
    return;
  }

  var button = document.getElementById("mission-start-button");
  var status = document.getElementById("mission-start-status");

  function value(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  function checked(id) {
    var el = document.getElementById(id);
    return !!(el && el.checked);
  }

  function say(text, isError) {
    if (!status) {
      return;
    }
    status.textContent = text;
    status.style.color = isError ? "var(--breach)" : "var(--slate)";
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    var target = value("target");
    if (!target) {
      say("Enter a target first.", true);
      document.getElementById("target").focus();
      return;
    }

    var payload = {
      target: target,
      profile: value("profile") || "recon",
      strategy: value("strategy") || "auto",
      agent_mode: value("agent_mode") || "deterministic",
      max_steps: parseInt(value("max_steps"), 10) || 20,
      require_approval: checked("require_approval"),
      dry_run: checked("dry_run"),
      lab: checked("lab")
    };

    var objective = value("objective");
    if (objective) {
      payload.objective = objective;
    }
    var missionName = value("mission_name");
    if (missionName) {
      payload.mission_name = missionName;
    }

    if (button) {
      button.disabled = true;
    }
    say("Starting…", false);

    fetch(form.dataset.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function (response) {
        return response.json().then(function (body) {
          return { ok: response.ok, body: body };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          throw new Error(result.body.detail || "The mission could not be started.");
        }
        window.location.href = result.body.detail_url;
      })
      .catch(function (error) {
        if (button) {
          button.disabled = false;
        }
        say(String(error.message || error), true);
      });
  });
})();
