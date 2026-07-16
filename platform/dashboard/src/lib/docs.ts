export const DOCS_BASE_URL = "https://docs.hexgate.ai";

export const DOC_PATHS = {
  tokens: "/platform/workflow",
  policies: "/policy/yaml-shape",
  playground: "/cli/serve",
  registerAgent: "/cli/register",
} as const;

export function docsUrl(path: string): string {
  return `${DOCS_BASE_URL}${path}`;
}
