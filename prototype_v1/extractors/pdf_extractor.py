"""
PDF extractor preserving page structure, sections, and tables using pdfplumber with pypdf fallback.
"""
import os
from typing import List, Dict, Any
from extractors.models import DocumentContent, ContentBlock

class PdfExtractor:
    @staticmethod
    def extract(file_path: str) -> DocumentContent:
        file_name = os.path.basename(file_path)
        blocks: List[ContentBlock] = []
        raw_text_parts: List[str] = []
        block_counter = 0
        total_pages = 0

        try:
            import pdfplumber
            with pdfplumber.open(file_path) as pdf:
                total_pages = len(pdf.pages)
                for page_idx, page in enumerate(pdf.pages, start=1):
                    # 1. Extract tables first to isolate them from plain text
                    tables = page.extract_tables()
                    for t_idx, tbl in enumerate(tables):
                        for r_idx, row in enumerate(tbl):
                            cleaned_row = [str(c).strip() if c is not None else "" for c in row]
                            if any(cleaned_row):
                                row_str = " | ".join(cleaned_row)
                                block = ContentBlock(
                                    block_id=f"pdf_p{page_idx}_tbl{t_idx}_r{r_idx}",
                                    block_type="table_row",
                                    text=row_str,
                                    location={"page": page_idx, "table": t_idx, "row": r_idx},
                                    style_metadata={"is_header": (r_idx == 0)}
                                )
                                blocks.append(block)
                                raw_text_parts.append(row_str)
                                block_counter += 1

                    # 2. Extract standard text paragraphs
                    text = page.extract_text() or ""
                    paras = [p.strip() for p in text.split("\n") if p.strip()]
                    
                    for p_idx, p_text in enumerate(paras):
                        # Avoid duplicating lines that are already table contents
                        if " | " in p_text and any(p_text in b.text for b in blocks if b.block_type == "table_row"):
                            continue

                        is_heading = len(p_text) < 70 and (p_text.isupper() or p_text.startswith(("1.", "2.", "3.", "Section", "CADENCE")))
                        is_bullet = p_text.startswith(("-", "•", "*", "▪"))

                        block = ContentBlock(
                            block_id=f"pdf_p{page_idx}_para{p_idx}",
                            block_type="heading" if is_heading else ("bullet" if is_bullet else "paragraph"),
                            text=p_text,
                            location={"page": page_idx, "line": p_idx},
                            style_metadata={"heading": is_heading}
                        )
                        blocks.append(block)
                        raw_text_parts.append(p_text)
                        block_counter += 1

        except Exception as e:
            # Fallback to pypdf
            import pypdf
            reader = pypdf.PdfReader(file_path)
            total_pages = len(reader.pages)
            for page_idx, page in enumerate(reader.pages, start=1):
                page_text = page.extract_text() or ""
                lines = [l.strip() for l in page_text.splitlines() if l.strip()]
                for l_idx, line in enumerate(lines):
                    block = ContentBlock(
                        block_id=f"pdf_fb_p{page_idx}_l{l_idx}",
                        block_type="paragraph",
                        text=line,
                        location={"page": page_idx, "line": l_idx}
                    )
                    blocks.append(block)
                    raw_text_parts.append(line)
                    block_counter += 1

        full_raw_text = "\n".join(raw_text_parts)
        metadata = {
            "page_count": total_pages,
            "source_type": "pdf"
        }

        return DocumentContent(
            file_name=file_name,
            file_type="pdf",
            raw_text=full_raw_text,
            blocks=blocks,
            metadata=metadata
        )
