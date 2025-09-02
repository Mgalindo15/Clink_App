// Using textbox for dob (dev only) --> basic normalization and matching (validation of dates done in backend)
export function normalizeDobInput(s) {
    const t = s.trim();
    // already iso
    if (/^\d{4}-\d{2}-\d{2}$/.test(t)) return t;
    // MM/DD/YYYY or MM-DD-YYYY --> destructure and rebuild regex
    const m = t.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{4})$/);
    if (m) {
        const [_, mm, dd, yyyy] = m;
        const MM = String(mm).padStart(2, "0");
        const DD = String(dd).padStart(2, "0");
        return `${yyyy}-${MM}-${DD}`;
    }
    throw new Error("DOB must be YYYY-MM-DD or MM/DD/YYYY");
}

// country: locale hash map
export function localeForCountry(countryCode) {
    const map = {
        US: "en-US",
        CA: "en-CA",
        GB: "en-GB",
        A: "en-AU",
    };
    return map[countryCode] ?? "en-US";
}

// JSON drop, pretty print
export function renderJSON(el, obj) {
    el.textContent = JSON.stringinfy(obj, null, 2);
}
