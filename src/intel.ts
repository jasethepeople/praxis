import { canonicalJson, sha256 } from "./canonical";
import type { Config } from "./config";
import type { PraxisDb } from "./db";
import type { IntelEvidence } from "./types";
import { ExploitDbIndex } from "./exploit-db";
import type { Fetcher } from "./net";

const sources = new Set(["openalex", "crossref", "unpaywall", "arxiv", "github", "nvd", "exploit_db"]);
const CACHE_MS = 12 * 60 * 60 * 1000;
const USER_AGENT = "PraxisIntelHub/0.1.0 (local-first metadata search)";

function decodeXml(value: string): string {
  return value.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)));
}

function xmlTag(block: string, tag: string): string | undefined {
  const match = block.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match ? decodeXml(match[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()) : undefined;
}

async function boundedText(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > maxBytes) throw new Error("Provider response exceeded size limit");
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("Provider response exceeded size limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function evidence(source: IntelEvidence["source"], access: IntelEvidence["access"], fields: Omit<IntelEvidence, "source" | "access" | "retrieved_at">): IntelEvidence {
  return { source, access, ...fields, retrieved_at: new Date().toISOString() };
}

export class IntelHub {
  private readonly exploitDb: ExploitDbIndex;

  constructor(private readonly db: PraxisDb, private readonly config: Config, fetcher: Fetcher = fetch) {
    this.exploitDb = new ExploitDbIndex(db, fetcher);
  }

  refreshExploitDb(): Promise<{ records: number; refreshed_at: string }> {
    return this.exploitDb.refresh();
  }

  async search(input: { query: string; sources?: string[]; include_security?: boolean; doi?: string }): Promise<{ query: string; results: IntelEvidence[]; providers: Array<{ source: string; status: "ok" | "cached" | "unavailable"; error?: string }> }> {
    const query = input.query.trim();
    if (!query || query.length > 500 || Buffer.byteLength(query) > 2000) throw new Error("query must be 1–500 characters");
    const requested = input.sources?.length ? [...new Set(input.sources)] : ["openalex", "crossref", "arxiv", "github"];
    if (requested.length > 8 || requested.some((source) => !sources.has(source))) throw new Error("Unsupported evidence source");
    if (input.include_security) {
      if (!requested.includes("nvd")) requested.push("nvd");
      if (!requested.includes("exploit_db")) requested.push("exploit_db");
    }
    const jobs = requested.map(async (source) => {
      const cacheKey = sha256(canonicalJson({ source, query: query.toLowerCase(), doi: input.doi ?? "" }));
      const cached = this.getCached(cacheKey);
      if (cached) return { source, status: "cached" as const, results: cached };
      try {
        const results = await this.searchSource(source, query, input.doi);
        this.putCached(cacheKey, source, results);
        return { source, status: "ok" as const, results };
      } catch (error) {
        return { source, status: "unavailable" as const, error: error instanceof Error ? error.message : "provider unavailable", results: [] as IntelEvidence[] };
      }
    });
    const responses = await Promise.all(jobs);
    const results = responses.flatMap((response) => response.results).slice(0, 80);
    return {
      query,
      results,
      providers: responses.map(({ source, status, error }) => ({ source, status, ...(error ? { error } : {}) })),
    };
  }

  private getCached(key: string): IntelEvidence[] | null {
    const row = this.db.sqlite.query("SELECT cached_at,response_json FROM intel_cache WHERE cache_key=?").get(key) as { cached_at: string; response_json: string } | null;
    if (!row || Date.now() - Date.parse(row.cached_at) > CACHE_MS) return null;
    try { return JSON.parse(row.response_json) as IntelEvidence[]; } catch { return null; }
  }

  private putCached(key: string, source: string, value: IntelEvidence[]): void {
    this.db.sqlite.query("INSERT INTO intel_cache(cache_key,provider,cached_at,response_json) VALUES(?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET cached_at=excluded.cached_at,response_json=excluded.response_json")
      .run(key, source, new Date().toISOString(), canonicalJson(value));
    this.db.sqlite.query("DELETE FROM intel_cache WHERE cached_at < ?").run(new Date(Date.now() - CACHE_MS * 2).toISOString());
  }

  private async searchSource(source: string, query: string, doi?: string): Promise<IntelEvidence[]> {
    if (source === "openalex") return this.openAlex(query);
    if (source === "crossref") return this.crossref(query);
    if (source === "arxiv") return this.arxiv(query);
    if (source === "github") return this.github(query);
    if (source === "nvd") return this.nvd(query);
    if (source === "exploit_db") return this.exploitDbSearch(query);
    if (source === "unpaywall") return doi ? this.unpaywall(doi) : [];
    return [];
  }

  private async getJson(url: string, headers: Record<string, string> = {}): Promise<unknown> {
    const response = await fetch(url, {         headers: { "user-agent": USER_AGENT, accept: "application/json", ...headers }, redirect: "error", signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return JSON.parse(await boundedText(response, 2_000_000));
  }

  private async getText(url: string): Promise<string> {
    const response = await fetch(url, { headers: { "user-agent": USER_AGENT, accept: "application/atom+xml,text/xml" }, redirect: "error", signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return boundedText(response, 2_000_000);
  }

  private async openAlex(query: string): Promise<IntelEvidence[]> {
    const url = `https://api.openalex.org/works?search=${encodeURIComponent(query)}&per-page=10&select=id,doi,display_name,publication_year,authorships,open_access,primary_location,biblio`;
    const payload = await this.getJson(url) as { results?: Array<Record<string, unknown>> };
    return (payload.results ?? []).slice(0, 10).map((work) => {
      const location = work.primary_location as Record<string, unknown> | null;
      const open = work.open_access as Record<string, unknown> | null;
      const authors = Array.isArray(work.authorships) ? work.authorships.slice(0, 12).flatMap((item) => {
        const author = (item as Record<string, unknown>).author as Record<string, unknown> | undefined;
        return typeof author?.display_name === "string" ? [author.display_name] : [];
      }) : [];
      const url = typeof location?.landing_page_url === "string" ? location.landing_page_url : typeof work.doi === "string" ? work.doi : undefined;
      const pdfUrl = typeof location?.pdf_url === "string" ? location.pdf_url : undefined;
      return evidence("openalex", open?.is_oa === true && pdfUrl ? "oa_pdf" : "metadata_only", {
        title: String(work.display_name ?? "Untitled"), doi: typeof work.doi === "string" ? work.doi.replace(/^https?:\/\/doi\.org\//, "") : undefined,
        url: pdfUrl ?? url, metadata: { openalex_id: work.id, year: work.publication_year, authors },
      });
    });
  }

  private async crossref(query: string): Promise<IntelEvidence[]> {
    const url = `https://api.crossref.org/works?query=${encodeURIComponent(query)}&rows=10`;
    const payload = await this.getJson(url) as { message?: { items?: Array<Record<string, unknown>> } };
    return (payload.message?.items ?? []).slice(0, 10).flatMap((item) => {
      const title = Array.isArray(item.title) ? item.title[0] : undefined;
      if (typeof title !== "string") return [];
      const authors = Array.isArray(item.author) ? item.author.slice(0, 12).flatMap((raw) => {
        const author = raw as Record<string, unknown>;
        return typeof author.given === "string" || typeof author.family === "string" ? [`${author.given ?? ""} ${author.family ?? ""}`.trim()] : [];
      }) : [];
      return [evidence("crossref", "metadata_only", { title, doi: typeof item.DOI === "string" ? item.DOI : undefined, url: typeof item.URL === "string" ? item.URL : undefined, metadata: { type: item.type, published: item.published, authors } })];
    });
  }

  private async arxiv(query: string): Promise<IntelEvidence[]> {
    const terms = query.split(/\s+/).filter(Boolean).slice(0, 8).join(" AND ");
    const url = `https://export.arxiv.org/api/query?search_query=${encodeURIComponent(`all:${terms}`)}&start=0&max_results=10&sortBy=relevance`;
    const xml = await this.getText(url);
    return [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].slice(0, 10).flatMap(([, block]) => {
      const title = xmlTag(block, "title");
      if (!title) return [];
      const id = xmlTag(block, "id");
      const published = xmlTag(block, "published");
      const authors = [...block.matchAll(/<author>([\s\S]*?)<\/author>/g)].slice(0, 12).flatMap(([, author]) => {
        const name = xmlTag(author, "name");
        return name ? [name] : [];
      });
      return [evidence("arxiv", "preprint", { title, url: id, metadata: { published, authors } })];
    });
  }

  private async github(query: string): Promise<IntelEvidence[]> {
    const payload = await this.getJson(`https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&sort=best-match&per_page=10`, {
      accept: "application/vnd.github+json", ...(this.config.githubToken ? { authorization: `Bearer ${this.config.githubToken}` } : {}),
    }) as { items?: Array<Record<string, unknown>> };
    return (payload.items ?? []).slice(0, 10).flatMap((repo) => typeof repo.full_name === "string" ? [evidence("github", "metadata_only", {
      title: repo.full_name, url: typeof repo.html_url === "string" ? repo.html_url : undefined,
      metadata: { description: repo.description, language: repo.language, stars: repo.stargazers_count, updated_at: repo.updated_at },
    })] : []);
  }

  private async exploitDbSearch(query: string): Promise<IntelEvidence[]> {
    const rows = await this.exploitDb.search(query, 10);
    return rows.map((row) => evidence("exploit_db", "metadata_only", {
      title: row.description || row.file_path,
      url: `https://www.exploit-db.com/exploits/${encodeURIComponent(row.edb_id)}`,
      metadata: {
        edb_id: row.edb_id,
        file_path: row.file_path,
        date_published: row.date_published,
        author: row.author,
        type: row.exploit_type,
        platform: row.platform,
        port: row.port,
        verified: row.verified === 1,
      },
    }));
  }

  private async nvd(query: string): Promise<IntelEvidence[]> {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=10`;
    const payload = await this.getJson(url, this.config.nvdApiKey ? { apiKey: this.config.nvdApiKey } : {}) as { vulnerabilities?: Array<Record<string, unknown>> };
    return (payload.vulnerabilities ?? []).slice(0, 10).flatMap((wrapper) => {
      const cve = wrapper.cve as Record<string, unknown> | undefined;
      if (!cve || typeof cve.id !== "string") return [];
      const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
      const description = descriptions.find((item) => (item as Record<string, unknown>).lang === "en") as Record<string, unknown> | undefined;
      return [evidence("nvd", "metadata_only", { title: cve.id, url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`, metadata: { published: cve.published, description: description?.value } })];
    });
  }

  private async unpaywall(doi: string): Promise<IntelEvidence[]> {
    if (!this.config.unpaywallEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.config.unpaywallEmail)) throw new Error("Unpaywall requires UNPAYWALL_EMAIL");
    const normalized = doi.trim().replace(/^https?:\/\/doi\.org\//i, "");
    if (!/^[0-9.]+\/[^\s]{3,250}$/.test(normalized)) throw new Error("Invalid DOI");
    const payload = await this.getJson(`https://api.unpaywall.org/v2/${encodeURIComponent(normalized)}?email=${encodeURIComponent(this.config.unpaywallEmail)}`) as Record<string, unknown>;
    const best = payload.best_oa_location as Record<string, unknown> | null;
    const pdfUrl = best && typeof best.url_for_pdf === "string" ? best.url_for_pdf : undefined;
    const landingUrl = best && typeof best.url_for_landing_page === "string" ? best.url_for_landing_page : undefined;
    return [evidence("unpaywall", pdfUrl ? "oa_pdf" : best ? "metadata_only" : "no_access", { title: typeof payload.title === "string" ? payload.title : undefined, doi: normalized, url: pdfUrl ?? landingUrl, metadata: { is_oa: payload.is_oa, oa_status: payload.oa_status } })];
  }
}
