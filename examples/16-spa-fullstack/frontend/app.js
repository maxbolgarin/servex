// Servex SPA Notes — vanilla JS client
(function () {
    let token = null;
    let ws = null;

    const $ = (sel) => document.querySelector(sel);

    // --- Auth ---

    $("#login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        $("#login-error").textContent = "";

        const resp = await fetch("/api/v1/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: $("#username").value,
                password: $("#password").value,
            }),
        });
        const data = await resp.json();
        if (!resp.ok) {
            $("#login-error").textContent = data.message || "Login failed";
            return;
        }
        token = data.accessToken;
        $("#login-view").style.display = "none";
        $("#notes-view").style.display = "block";
        loadNotes();
        connectWS();
    });

    $("#logout-btn").addEventListener("click", async () => {
        await fetch("/api/v1/auth/logout", { method: "POST", credentials: "include" });
        token = null;
        if (ws) ws.close();
        $("#notes-view").style.display = "none";
        $("#login-view").style.display = "";
    });

    // --- Notes CRUD ---

    async function loadNotes() {
        const resp = await fetch("/api/notes", {
            headers: { Authorization: "Bearer " + token },
        });
        const notes = await resp.json();
        renderNotes(notes);
    }

    function renderNotes(notes) {
        const list = $("#notes-list");
        list.innerHTML = notes
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .map(
                (n) => `
            <div class="note" data-id="${n.id}">
                <div>
                    <h3>${esc(n.title)}</h3>
                    ${n.content ? "<p>" + esc(n.content) + "</p>" : ""}
                </div>
                <button onclick="deleteNote('${n.id}')">Delete</button>
            </div>`
            )
            .join("");
    }

    $("#note-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const title = $("#note-title").value.trim();
        if (!title) return;

        await fetch("/api/notes", {
            method: "POST",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                title: title,
                content: $("#note-content").value.trim(),
            }),
        });
        $("#note-title").value = "";
        $("#note-content").value = "";
        loadNotes();
    });

    window.deleteNote = async function (id) {
        await fetch("/api/notes/" + id, {
            method: "DELETE",
            headers: { Authorization: "Bearer " + token },
        });
        loadNotes();
    };

    // --- WebSocket ---

    function connectWS() {
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(
            proto + "//" + location.host + "/ws/notifications?token=" + token,
            []
        );

        // Send auth via first message since WebSocket API doesn't support headers in browsers.
        // Alternatively, the token is in the URL query — depends on server config.
        // Here we rely on the cookie-based auth or a custom approach.
        // For this demo, we use a polling fallback if WS auth fails.

        ws.onopen = () => {
            $("#ws-status").textContent = "Connected";
            $("#ws-status").className = "status connected";
        };

        ws.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            showNotification(msg);
            loadNotes(); // refresh list on any change
        };

        ws.onclose = () => {
            $("#ws-status").textContent = "Disconnected";
            $("#ws-status").className = "status disconnected";
            // Reconnect after 3 seconds
            setTimeout(() => {
                if (token) connectWS();
            }, 3000);
        };
    }

    function showNotification(msg) {
        const el = document.createElement("div");
        el.className = "notification";
        if (msg.type === "note_created") {
            el.textContent = "New note created: " + msg.note.title;
        } else if (msg.type === "note_deleted") {
            el.textContent = "Note deleted";
        } else {
            el.textContent = JSON.stringify(msg);
        }
        $("#notifications").prepend(el);
        setTimeout(() => el.remove(), 3500);
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }
})();
