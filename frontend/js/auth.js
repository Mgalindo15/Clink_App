import { Api } from "./api.js";

export async function loginFlow(username, password) {
    // set httpOnly cookie -->
    const tok = await Api.login(username, password);
    // if (tok?.access_token) localStorage.setItem("access_token", tok.access_token); 
    //              --> Secondary validation via js header validation || not in use (uncomment api.js lines 11-13 && auth.js line 13, if using)
    return await Api.me();
}

export async function logoutFlow() {
    await Api.logout();
    // localStorage.removeItem("access_token");
}

export async function requireAdminOrRedirect() {
    try {
        // pull logged in profile info
        const me = await Api.me();
        // not admin --> redirect
        if (!me.is_admin) {
            alert("Admin only.");
            window.location.href = "/index.html";
            return null;
        }
        // admin --> continue
        return me;
    } catch {
        // error redirect (security)
        window.location.href = "/index.html";
        return null;
    }
}
