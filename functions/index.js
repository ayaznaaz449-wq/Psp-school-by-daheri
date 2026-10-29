const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const crypto = require("crypto");

initializeApp();
const auth = getAuth();
const db = getFirestore();
const PROJECT_SUFFIX = "people-school-dda48.firebaseapp.com";
function cleanUsername(value) {
  const username = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
    throw new HttpsError("invalid-argument", "Username must be 3–32 characters (letters, numbers, dot, _ or -).");
  }
  return username;
}
function internalEmail(username) { return username + "@" + PROJECT_SUFFIX; }
async function createAccount(username, password, role, name) {
  if (typeof password !== "string" || password.length < 8) {
    throw new HttpsError("invalid-argument", "Password must be at least 8 characters.");
  }
  let user;
  try {
    user = await auth.createUser({ email: internalEmail(username), password, displayName: name || username });
    await db.doc("users/" + user.uid).set({
      username, name: name || username, role, active: true,
      createdAt: FieldValue.serverTimestamp()
    });
    return { username, role };
  } catch (e) {
    if (user) await auth.deleteUser(user.uid).catch(() => {});
    if (e instanceof HttpsError) throw e;
    if (e.code === "auth/email-already-exists") throw new HttpsError("already-exists", "That username is already in use.");
    throw new HttpsError("internal", "Could not create account.");
  }
}
exports.bootstrapPrincipal = onCall(async (request) => {
  const username = cleanUsername(request.data.username);
  const count = await db.collection("users").where("role", "==", "principal").limit(1).get();
  if (!count.empty) throw new HttpsError("failed-precondition", "Principal setup has already been completed.");
  // Reserve setup atomically so two first-time users cannot both become Principal.
  const lock = db.doc("_system/principalBootstrap");
  await db.runTransaction(async tx => {
    const snap = await tx.get(lock);
    const principals = await tx.get(db.collection("users").where("role", "==", "principal").limit(1));
    if (snap.exists || !principals.empty) throw new HttpsError("failed-precondition", "Principal setup has already been completed.");
    tx.create(lock, { claimedAt: FieldValue.serverTimestamp(), username });
  });
  try {
    return await createAccount(username, request.data.password, "principal", String(request.data.name || "Principal").trim());
  } catch (e) {
    await lock.delete().catch(() => {});
    throw e;
  }
});
exports.createStaffAccount = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Please sign in first.");
  const actor = await db.doc("users/" + request.auth.uid).get();
  if (!actor.exists || actor.data().active !== true || actor.data().role !== "principal") {
    throw new HttpsError("permission-denied", "Only the Principal can create accounts.");
  }
  const username = cleanUsername(request.data.username);
  const allowed = ["admin", "teacher", "accountant", "student", "parent"];
  const role = String(request.data.role || "");
  if (!allowed.includes(role)) throw new HttpsError("invalid-argument", "Select a valid staff role.");
  return createAccount(username, request.data.password, role, String(request.data.name || username).trim());
});
