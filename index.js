import express from 'express';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

const app = express();
app.use(express.json());

// axe renvoie l'impact en anglais → on mappe vers tes 3 niveaux
const SEVERITE = { critical: 'critique', serious: 'majeur', moderate: 'mineur', minor: 'mineur' };
const MAX_PAGES_LIMIT = 50;   // garde-fou anti-crawl infini
const PAGE_TIMEOUT = 30000;   // 30s max par page

// transforme un tag axe "wcag143" en critère "1.4.3"
function critereWcag(tags = []) {
  for (const t of tags) {
    const m = /^wcag(\d)(\d)(\d+)$/.exec(t);
    if (m) return `${m[1]}.${m[2]}.${m[3]}`;
  }
  return null;
}

function normalize(href) {
  try {
    const u = new URL(href);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    u.hash = '';
    return u.toString();
  } catch { return null; }
}

function memeDomaine(a, b) {
  try { return new URL(a).hostname === new URL(b).hostname; }
  catch { return false; }
}

app.get('/', (req, res) => res.send('Scanner accessibilité OK'));

app.post('/scan', async (req, res) => {
  // sécurité optionnelle : actif seulement si tu définis API_KEY dans Render
  if (process.env.API_KEY && req.get('x-api-key') !== process.env.API_KEY) {
    return res.status(401).json({ error: 'non autorisé' });
  }

  const { url, max_pages } = req.body || {};
  const start = url ? normalize(url) : null;
  if (!start) return res.status(400).json({ error: 'url manquante ou invalide' });

  const maxPages = Math.min(Number(max_pages) || 10, MAX_PAGES_LIMIT);

  let browser;
  try {
    browser = await chromium.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const context = await browser.newContext();

    const visited = new Set();
    const queue = [start];
    const pages = [];

    while (queue.length > 0 && visited.size < maxPages) {
      const current = queue.shift();
      if (visited.has(current)) continue;
      visited.add(current);

      const page = await context.newPage();
      try {
        await page.goto(current, { waitUntil: 'domcontentloaded', timeout: PAGE_TIMEOUT });

        const axe = await new AxeBuilder({ page })
          .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']) // = niveau EAA
          .analyze();

        const violations = [];
        for (const v of axe.violations) {
          for (const node of v.nodes) {
            violations.push({
              critere_wcag: critereWcag(v.tags) || v.id,
              severite: SEVERITE[v.impact] || 'mineur',
              selecteur: Array.isArray(node.target) ? node.target.join(' ') : String(node.target),
              description_technique: v.help,
            });
          }
        }

        pages.push({ url_page: current, violations });

        // récupère les liens internes pour continuer le crawl
        const hrefs = await page.$$eval('a[href]', as => as.map(a => a.href));
        for (const h of hrefs) {
          const n = normalize(h);
          if (n && memeDomaine(n, start) && !visited.has(n) && !queue.includes(n)) {
            queue.push(n);
          }
        }
      } catch (e) {
        pages.push({ url_page: current, violations: [], erreur: 'page non analysée : ' + e.message });
      } finally {
        await page.close();
      }
    }

    await browser.close();
    res.json({ pages });
  } catch (e) {
    if (browser) await browser.close().catch(() => {});
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Scanner en écoute sur le port ${PORT}`));
