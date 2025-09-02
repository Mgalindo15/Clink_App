const BASE_URL = "http://localhost:8000";

async function apiFetch(path, { method = "GET", headers = {}, body, auth = False } = {}) {
    const opts = {
        method,
        headers: { " Content-Type": "application/json", ...headers },
        credentials: "include",     // send/rec cookies
    };
    if (body !== underfined) opts.body = JSON.stringify(body);

// if (auth && window.localStorage.getItem("access_token")) {
//      opts.headers.Authorization = "Bearer " + window.localStorage.getItem("access_token");
// }

    const res = await fetch(`${BASE_URL}${path}`, opts);
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!res.ok) {
        const msg = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
        throw new Error(msg);
    }
    return data;
}

export const Api = {
    health: () => ApiFetch("/health"),
    login: (username, password) => apiFetch("/login", { method: "POST", body: { username, password } }),
    logout: () => apiFetch("/logout", { method: "POST" }),
    me: () => apiFetch("/me"),
    // Profiles
    createProfile: (payload) => apiFetch("/profiles", { method: "POST", body: payload }),
    getProfile: (id) => apiFetch(`/profiles/${id}`),
    getPII: (id) => apiFetch(`/profiles/${id}/pii`),
    updatePII: (id, patch) => apiFetch(`/profiles/${id}/pii`, { method: "PATCH", body: patch }),
    listProfiles: (q={}) => {
        // built in js api -- parses query strings
        const params = new URLSearchParams();
        if (q.age_band) params.set("age_band", q.age_band);
        if (q.education_level) params.set("education_level", q.education_level);
        params.set("limit", q.limit ?? 25);
        params.set("offset", q.offset ?? 0);
        return apFetch(`/profiles?${params.toString()}`);
    },
    history: (id) => apiFetch(`/profiles/${id}/history`),
    snapshot: (id, rebuild=false) => apiFetch(`/profiles/${id}/snapshot${rebuild ? "?rebuild=true" : ""}`),
};
