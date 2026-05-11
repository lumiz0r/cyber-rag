"""
CYBER-RAG Notion Client
Fetches pages and content from the Notion API
"""
import httpx
from typing import Optional

# Per-request timeout (seconds). Keep short so a dead page doesn't freeze the sync.
_REQUEST_TIMEOUT = 15.0


RICH_TEXT_BLOCK_TYPES = {
    "paragraph", "heading_1", "heading_2", "heading_3",
    "bulleted_list_item", "numbered_list_item", "quote",
    "callout", "toggle", "code", "to_do",
}

HEADING_TYPES = {"heading_1", "heading_2", "heading_3"}


class NotionClient:
    def __init__(self, token: str):
        self.token = token
        self.base = "https://api.notion.com/v1"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Notion-Version": "2022-06-28",
            "Content-Type": "application/json",
        }
        self._http = httpx.Client(timeout=_REQUEST_TIMEOUT)

    # ──────────────────────────────────────────────
    # Search / list pages
    # ──────────────────────────────────────────────

    def search_pages(self, query: str = "", limit: Optional[int] = None) -> list[dict]:
        """Return all page objects the integration can access.

        Pass limit=N to cap results; omit (or None) to fetch every page via
        automatic cursor-based pagination.
        """
        pages: list[dict] = []
        start_cursor: Optional[str] = None

        while True:
            payload: dict = {
                "filter": {"value": "page", "property": "object"},
                "page_size": 100,
            }
            if query:
                payload["query"] = query
            if start_cursor:
                payload["start_cursor"] = start_cursor

            resp = self._http.post(f"{self.base}/search", headers=self.headers, json=payload)
            data = resp.json()

            if "results" not in data:
                break

            pages.extend(data["results"])

            if limit is not None and len(pages) >= limit:
                pages = pages[:limit]
                break

            if not data.get("has_more"):
                break
            start_cursor = data.get("next_cursor")

        return pages

    # ──────────────────────────────────────────────
    # Block content
    # ──────────────────────────────────────────────

    def _get_block_children_page(self, block_id: str, cursor: Optional[str] = None) -> dict:
        params: dict = {"page_size": 100}
        if cursor:
            params["start_cursor"] = cursor
        resp = self._http.get(
            f"{self.base}/blocks/{block_id}/children",
            headers=self.headers,
            params=params,
        )
        return resp.json()

    def get_block_children(self, block_id: str, depth: int = 0, max_depth: int = 2) -> list[dict]:
        """Recursively fetch block children up to max_depth.

        max_depth=2 covers the vast majority of real note structures (page →
        section → list items) while avoiding the exponential API-call blowup
        that deeper nesting causes.
        """
        if depth > max_depth:
            return []

        blocks: list[dict] = []
        cursor: Optional[str] = None

        try:
            while True:
                data = self._get_block_children_page(block_id, cursor)
                if "results" not in data:
                    break

                for block in data["results"]:
                    blocks.append(block)
                    btype = block.get("type", "")
                    # Only recurse into block types that carry meaningful text
                    if block.get("has_children") and btype in (
                        "toggle", "bulleted_list_item", "numbered_list_item",
                        "quote", "callout", "column_list", "column",
                        "synced_block", "template",
                    ) and depth < max_depth:
                        children = self.get_block_children(block["id"], depth + 1, max_depth)
                        blocks.extend(children)

                if not data.get("has_more"):
                    break
                cursor = data.get("next_cursor")

        except httpx.TimeoutException:
            pass  # return whatever we collected before the timeout

        return blocks

    # ──────────────────────────────────────────────
    # Text extraction
    # ──────────────────────────────────────────────

    @staticmethod
    def _rich_text_to_str(rich_text: list) -> str:
        return "".join(rt.get("plain_text", "") for rt in rich_text)

    def extract_text(self, blocks: list[dict]) -> str:
        parts: list[str] = []

        for block in blocks:
            btype = block.get("type", "")
            bcontent = block.get(btype, {})

            if btype in RICH_TEXT_BLOCK_TYPES:
                text = self._rich_text_to_str(bcontent.get("rich_text", []))
                if not text.strip():
                    continue

                if btype in HEADING_TYPES:
                    level = {"heading_1": "#", "heading_2": "##", "heading_3": "###"}[btype]
                    parts.append(f"\n{level} {text}\n")
                elif btype == "code":
                    lang = bcontent.get("language", "")
                    parts.append(f"\n```{lang}\n{text}\n```\n")
                elif btype in ("bulleted_list_item", "numbered_list_item"):
                    parts.append(f"• {text}")
                elif btype == "to_do":
                    checked = "✓" if bcontent.get("checked") else "○"
                    parts.append(f"{checked} {text}")
                else:
                    parts.append(text)

            elif btype == "divider":
                parts.append("\n---\n")
            elif btype == "image":
                caption = self._rich_text_to_str(bcontent.get("caption", []))
                parts.append(f"[IMAGE{': ' + caption if caption else ''}]")
            elif btype == "table_of_contents":
                pass  # skip TOC blocks

        return "\n".join(parts)

    def get_page_content(self, page_id: str) -> str:
        blocks = self.get_block_children(page_id)
        return self.extract_text(blocks)

    # ──────────────────────────────────────────────
    # Metadata helpers
    # ──────────────────────────────────────────────

    def get_page_title(self, page: dict) -> str:
        for _key, prop in page.get("properties", {}).items():
            if prop.get("type") == "title":
                return self._rich_text_to_str(prop.get("title", []))
        return "Untitled"

    def get_page_url(self, page: dict) -> str:
        return page.get("url", "")

    def get_page_tags(self, page: dict) -> list[str]:
        """Try to extract tags/multi-select properties."""
        tags: list[str] = []
        for prop in page.get("properties", {}).values():
            if prop.get("type") == "multi_select":
                tags.extend(opt.get("name", "") for opt in prop.get("multi_select", []))
        return tags

    def close(self):
        self._http.close()
