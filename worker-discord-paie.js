
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGIN || "").replace(/\/$/, "");

    const cors = {
      "Access-Control-Allow-Origin": allowed,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Vary": "Origin"
    };

    if (!allowed || origin.replace(/\/$/, "") !== allowed) {
      return new Response("Origin non autorisée", { status: 403 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== "POST") {
      return json({ error: "Méthode non autorisée" }, 405, cors);
    }

    try {
      const auth = request.headers.get("Authorization") || "";
      const match = auth.match(/^Bearer\s+(.+)$/i);

      if (!match) return json({ error: "Authentification requise" }, 401, cors);

      const verify = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ idToken: match[1] })
        }
      );

      if (!verify.ok) {
        return json({ error: "Session Firebase invalide" }, 401, cors);
      }

      const identity = await verify.json();
      if (!identity.users?.length) {
        return json({ error: "Utilisateur introuvable" }, 401, cors);
      }

      const incoming = await request.formData();
      const file = incoming.get("file");
      const data = JSON.parse(incoming.get("payload") || "{}");

      if (!(file instanceof File) || file.type !== "image/png") {
        throw new Error("Fichier PNG invalide");
      }

      if (file.size > 8 * 1024 * 1024) {
        throw new Error("Image trop volumineuse");
      }

      const safe = (v) => String(v || "Non renseigné").slice(0, 180);
      const filename = safe(data.filename).replace(/[^a-zA-Z0-9_.-]/g, "_");

      const discordForm = new FormData();
      discordForm.append("files[0]", file, filename);

      discordForm.append("payload_json", JSON.stringify({
        content: "🧾 **Nouvelle fiche de paie — paiement validé**",
        embeds: [{
          title: "Sécurité Événements de la Ville",
          color: 0x22c55e,
          fields: [
            { name: "Agent", value: safe(data.agent), inline: true },
            { name: "Matricule", value: safe(data.matricule), inline: true },
            { name: "Poste", value: safe(data.poste), inline: true },
            { name: "Période", value: safe(data.periode), inline: true },
            { name: "Net versé", value: safe(data.montant), inline: true },
            { name: "Date", value: safe(data.date), inline: true }
          ],
          image: { url: `attachment://${filename}` },
          footer: { text: "Bulletin généré automatiquement" }
        }],
        allowed_mentions: { parse: [] }
      }));

      const sent = await fetch(env.DISCORD_WEBHOOK_URL, {
        method: "POST",
        body: discordForm
      });

      if (!sent.ok) {
        throw new Error("Erreur lors de l'envoi Discord : " + sent.status);
      }

      return json({ ok: true }, 200, cors);

    } catch (error) {
      return json({ error: error.message }, 500, cors);
    }
  }
};

function json(value, status, headers) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      ...headers,
      "Content-Type": "application/json"
    }
  });
}
