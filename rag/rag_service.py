"""
RAG service for defense rule generation.

This version is optimized for WAF rule-authoring documents:
- preserves procedural steps, syntax blocks, rule snippets, tables, and JSON examples
- keeps global chunk ids per source file, including PDF page metadata
- expands neighbor chunks from the FAISS docstore
- receives attack_type directly from caller and only normalizes it; payload guessing is fallback-only
"""

import os
import json
import hashlib
import re
from typing import List, Dict, Any, Optional, Tuple

from sentence_transformers import CrossEncoder
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import TextLoader, PyPDFLoader, Docx2txtLoader
try:
    from langchain_community.document_loaders import PyMuPDFLoader
except Exception:
    PyMuPDFLoader = None
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
import torch


RAG_INDEX_VERSION = "structure_aware_v2_pymupdf_pages_global_chunks"


class CrossEncoderReranker:
    """Re-rank retrieved documents using a cross-encoder."""

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = CrossEncoder(model_name, device=device)

    def rerank(self, query: str, documents: List[Document], top_k: int = 5) -> List[Tuple[Document, float]]:
        """Return top_k documents sorted by raw cross-encoder score."""
        if not documents:
            return []

        pairs = [[query, doc.page_content] for doc in documents]
        scores = self.model.predict(pairs)

        doc_score_pairs = [(doc, float(score)) for doc, score in zip(documents, scores)]
        doc_score_pairs.sort(key=lambda x: x[1], reverse=True)
        return doc_score_pairs[:top_k]


class DocumentIndexManager:
    """Manages document indexing and change detection."""

    def __init__(self, docs_folder: str, index_file: str = ".rag_index.json", index_version: str = RAG_INDEX_VERSION):
        self.docs_folder = docs_folder
        self.index_file = os.path.join(docs_folder, index_file)
        self.index_version = index_version
        self.current_index = {}

    def _compute_file_hash(self, filepath: str) -> str:
        """Compute MD5 hash of file content."""
        hasher = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Warning: Failed to hash {filepath}: {str(e)}")
            return ""

    def _scan_documents(self) -> Dict[str, Dict[str, Any]]:
        """Scan all documents and build index."""
        index = {
            "__rag_config__": {
                "index_version": self.index_version,
                "chunking_strategy": "structure_aware_v2",
                "loader_preference": "PyMuPDFLoader_then_PyPDFLoader",
            }
        }

        if not os.path.exists(self.docs_folder):
            return index

        data_types = ["Rules", "XSS", "SQLi"]
        waf_types = ["Cloudflare", "ModSecurity", "AWS", "Naxsi"]

        for data_type in data_types:
            folder_path = os.path.join(self.docs_folder, data_type)
            if not os.path.exists(folder_path):
                continue

            if data_type == "Rules":
                for waf_type in waf_types:
                    waf_folder_path = os.path.join(folder_path, waf_type)
                    if not os.path.exists(waf_folder_path):
                        continue

                    files = [
                        f for f in os.listdir(waf_folder_path)
                        if os.path.isfile(os.path.join(waf_folder_path, f))
                    ]
                    for filename in files:
                        if not filename.endswith((".txt", ".pdf", ".docx", ".md")):
                            continue

                        file_path = os.path.join(waf_folder_path, filename)
                        stats = os.stat(file_path)
                        index[file_path] = {
                            "filename": filename,
                            "data_type": data_type,
                            "waf_type": waf_type,
                            "size": stats.st_size,
                            "modified": stats.st_mtime,
                            "hash": self._compute_file_hash(file_path),
                        }
            else:
                files = [
                    f for f in os.listdir(folder_path)
                    if os.path.isfile(os.path.join(folder_path, f))
                ]
                for filename in files:
                    if not filename.endswith((".txt", ".pdf", ".docx", ".md")):
                        continue

                    file_path = os.path.join(folder_path, filename)
                    stats = os.stat(file_path)
                    index[file_path] = {
                        "filename": filename,
                        "data_type": data_type,
                        "waf_type": "None",
                        "size": stats.st_size,
                        "modified": stats.st_mtime,
                        "hash": self._compute_file_hash(file_path),
                    }

        return index

    def load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load saved index from disk."""
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load index: {str(e)}")
        return {}

    def save_index(self, index: Dict[str, Dict[str, Any]]):
        """Save index to disk."""
        try:
            os.makedirs(self.docs_folder, exist_ok=True)
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(index, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Failed to save index: {str(e)}")

    def needs_rebuild(self) -> Tuple[bool, str]:
        """
        Check if vector store needs rebuild.

        Returns:
            (needs_rebuild: bool, reason: str)
        """
        old_index = self.load_index()
        new_index = self._scan_documents()
        self.current_index = new_index

        if not old_index:
            return True, "No previous index found"

        if old_index.get("__rag_config__") != new_index.get("__rag_config__"):
            return True, "RAG indexing/chunking configuration changed"

        old_files = {k: v for k, v in old_index.items() if not k.startswith("__")}
        new_files = {k: v for k, v in new_index.items() if not k.startswith("__")}

        added = set(new_files.keys()) - set(old_files.keys())
        if added:
            return True, f"Added {len(added)} new file(s)"

        removed = set(old_files.keys()) - set(new_files.keys())
        if removed:
            return True, f"Removed {len(removed)} file(s)"

        modified = []
        for filepath in new_files.keys():
            if filepath in old_files and new_files[filepath]["hash"] != old_files[filepath]["hash"]:
                modified.append(filepath)

        if modified:
            return True, f"Modified {len(modified)} file(s)"

        return False, "No changes detected"

    def save_current_index(self):
        """Save current index to disk."""
        self.save_index(self.current_index)


class RAGDefenseService:
    """
    RAG-enhanced defense service with persistent vector store, WAF-specific filtering,
    and document-structure-aware chunking.
    """

    def __init__(
        self,
        docs_folder: str = "./docs/",
        vector_store_path: str = "./vector_store/",
        enable_rag: bool = True,
        force_rebuild: bool = False,
    ):
        self.enable_rag = enable_rag
        self.docs_folder = docs_folder
        self.vector_store_path = vector_store_path
        self.vector_store = None
        self.retriever = None
        self.reranker = None
        self.chunk_lookup = None
        self.index_manager = DocumentIndexManager(docs_folder, index_version=RAG_INDEX_VERSION)

        if self.enable_rag:
            self._initialize_rag(force_rebuild)

    def _initialize_rag(self, force_rebuild: bool = False):
        """Initialize all RAG components."""
        print("Initializing RAG service...")

        try:
            needs_rebuild, reason = self.index_manager.needs_rebuild()

            if force_rebuild:
                print("Force rebuild requested")
                needs_rebuild = True
                reason = "Force rebuild"

            if not needs_rebuild and os.path.exists(self.vector_store_path):
                print("No changes detected - loading existing vector store...")
                self._load_vector_store()
            else:
                print(f"Rebuild required: {reason}")
                self._build_vector_store()

            print("[4/4] Loading re-ranker...")
            self.reranker = CrossEncoderReranker()
            print("      Re-ranker ready")

            print("RAG service initialized successfully\n")

        except Exception as e:
            print(f"Error: Failed to initialize RAG: {str(e)}")
            self.enable_rag = False

    def _load_vector_store(self):
        """Load existing vector store from disk."""
        try:
            print("[1/4] Loading embeddings model...")
            embedding_kwargs = {"device": "cuda" if torch.cuda.is_available() else "cpu"}
            embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-mpnet-base-v2",
                model_kwargs=embedding_kwargs,
            )
            print("      Embeddings ready")

            print("[2/4] Loading vector store from disk...")
            self.vector_store = FAISS.load_local(
                self.vector_store_path,
                embeddings,
                allow_dangerous_deserialization=True,
            )
            self.chunk_lookup = None
            print("      Vector store loaded")

            print("[3/4] Setting up retriever...")
            self.retriever = self.vector_store.as_retriever(search_kwargs={"k": 12})
            print("      Retriever ready")

        except Exception as e:
            print(f"Warning: Failed to load vector store: {str(e)}")
            print("Rebuilding from scratch...")
            self._build_vector_store()

    def _build_vector_store(self):
        """Build new vector store from documents."""
        print("[1/4] Loading documents...")
        all_docs = self._load_documents()
        if not all_docs:
            print("Warning: No documents loaded, RAG will be disabled")
            self.enable_rag = False
            return
        print(f"      Loaded {len(all_docs)} document units")

        print("[2/4] Chunking documents...")
        chunks = self._chunk_documents(all_docs)
        print(f"      Created {len(chunks)} chunks")

        print("[3/4] Creating vector store...")
        embedding_kwargs = {"device": "cuda" if torch.cuda.is_available() else "cpu"}
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-mpnet-base-v2",
            model_kwargs=embedding_kwargs,
        )

        print(f"      Generating embeddings and building FAISS index... {embedding_kwargs}")
        self.vector_store = FAISS.from_documents(chunks, embeddings)
        self.chunk_lookup = None

        print("      Saving vector store to disk...")
        os.makedirs(self.vector_store_path, exist_ok=True)
        self.vector_store.save_local(self.vector_store_path)

        self.index_manager.save_current_index()
        print("      Vector store ready and saved")

        self.retriever = self.vector_store.as_retriever(search_kwargs={"k": 12})

    def _load_single_file(self, file_path: str, filename: str, data_type: str, waf_type: str) -> List[Document]:
        """Load a single file and preserve page metadata when available."""
        if filename.endswith(".txt") or filename.endswith(".md"):
            loader = TextLoader(file_path, encoding="utf-8")
            file_type = "txt" if filename.endswith(".txt") else "md"
        elif filename.endswith(".pdf"):
            if PyMuPDFLoader is not None:
                loader = PyMuPDFLoader(file_path)
            else:
                loader = PyPDFLoader(file_path)
            file_type = "pdf"
        elif filename.endswith(".docx"):
            loader = Docx2txtLoader(file_path)
            file_type = "docx"
        else:
            return []

        docs = loader.load()
        rel_path = os.path.relpath(file_path, self.docs_folder)

        normalized_docs: List[Document] = []
        for doc in docs:
            original_meta = dict(doc.metadata or {})

            page_index = original_meta.get("page")
            page_number = None
            if isinstance(page_index, int):
                page_number = page_index + 1
            elif isinstance(original_meta.get("page_number"), int):
                page_number = original_meta.get("page_number")
                page_index = page_number - 1

            doc.metadata = {
                "source": filename,
                "data_type": data_type,
                "waf_type": waf_type,
                "file_type": file_type,
                "file_path": file_path,
                "doc_rel_path": rel_path,
                "page": page_number,
                "page_index": page_index if isinstance(page_index, int) else None,
            }
            normalized_docs.append(doc)

        return normalized_docs

    def _load_documents(self) -> List[Document]:
        """Load documents from structured folders."""
        all_docs: List[Document] = []

        if not os.path.exists(self.docs_folder):
            print(f"Warning: Documents folder not found: {self.docs_folder}")
            return all_docs

        data_types = ["Rules", "XSS", "SQLi"]
        waf_types = ["Cloudflare", "ModSecurity", "AWS", "Naxsi"]

        for data_type in data_types:
            folder_path = os.path.join(self.docs_folder, data_type)
            if not os.path.exists(folder_path):
                continue

            if data_type == "Rules":
                for waf_type in waf_types:
                    waf_folder_path = os.path.join(folder_path, waf_type)
                    if not os.path.exists(waf_folder_path):
                        continue

                    files = [
                        f for f in os.listdir(waf_folder_path)
                        if os.path.isfile(os.path.join(waf_folder_path, f))
                    ]

                    for filename in files:
                        if not filename.endswith((".txt", ".pdf", ".docx", ".md")):
                            continue
                        file_path = os.path.join(waf_folder_path, filename)
                        try:
                            all_docs.extend(self._load_single_file(file_path, filename, data_type, waf_type))
                        except Exception as e:
                            print(f"Warning: Failed to load {filename}: {str(e)}")
            else:
                files = [
                    f for f in os.listdir(folder_path)
                    if os.path.isfile(os.path.join(folder_path, f))
                ]

                for filename in files:
                    if not filename.endswith((".txt", ".pdf", ".docx", ".md")):
                        continue
                    file_path = os.path.join(folder_path, filename)
                    try:
                        all_docs.extend(self._load_single_file(file_path, filename, data_type, "None"))
                    except Exception as e:
                        print(f"Warning: Failed to load {filename}: {str(e)}")

        return all_docs

    # ---------------------------------------------------------------------
    # Structure-aware chunking
    # ---------------------------------------------------------------------

    def _normalize_document_text(self, text: str, file_type: str = "", source: str = "") -> str:
        """Normalize extraction artifacts without destroying rule syntax."""
        if not text:
            return ""

        text = text.replace("\u00a0", " ")
        text = text.replace("\u200b", "")
        text = text.replace("\ufeff", "")
        text = text.replace("\r\n", "\n").replace("\r", "\n")

        # Fix common PDF hyphenation such as "rule-\nset" -> "ruleset".
        if file_type == "pdf":
            text = re.sub(r"(?<=\w)-\n(?=\w)", "", text)

        # Normalize excessive empty lines but keep paragraph boundaries.
        text = re.sub(r"\n{4,}", "\n\n\n", text)
        return text.strip()

    def _is_markdown_heading(self, line: str) -> bool:
        return bool(re.match(r"^\s{0,3}#{1,6}\s+\S+", line))

    def _is_doc_heading_line(self, line: str) -> bool:
        s = line.strip()
        if not s:
            return False

        if self._is_markdown_heading(s):
            return True

        if len(s) > 140:
            return False

        lower = s.lower()
        if lower.startswith((
            "note:", "warning:", "tip:", "important:", "example:",
            "open ", "choose ", "select ", "enter ", "set ", "for ", "under ",
            "(optional)", "if ", "when ",
        )):
            return False

        if s.endswith(".") and not re.search(r"\b(rule|rules|syntax|statement|directive|directives|example|configuration|functions|operators|values|actions|fields)\b", lower):
            return False

        heading_keywords = [
            "short description", "resolution", "rule syntax", "rule example",
            "create ", "use ", "add ", "configure ", "editing ", "creating ",
            "statement", "statements", "rules", "rule actions", "rule statements",
            "operators", "functions", "values", "fields", "directives",
            "internal rule", "mainrule", "basicrule", "transformation",
            "match statement", "xss", "sql injection", "regex match",
        ]
        if any(k in lower for k in heading_keywords):
            return True

        # Short title-case lines in docx exports are often headings.
        words = s.split()
        if 1 <= len(words) <= 8 and not re.search(r"[.;,]$", s):
            alpha_words = [w for w in words if re.search(r"[A-Za-z]", w)]
            if alpha_words and sum(1 for w in alpha_words if w[:1].isupper()) >= max(1, len(alpha_words) // 2):
                return True

        return False

    def _is_instruction_line(self, line: str) -> bool:
        s = line.strip()
        if not s:
            return False

        lower = s.lower()
        if re.match(r"^(step\s+\d+[:.]|\d+[.)]\s+)", lower):
            return True

        if lower.startswith((
            "complete the following steps",
            "to create", "to edit", "to add", "to configure", "to delete",
            "open ", "choose ", "select ", "enter ", "set ", "find ",
            "in the ", "under ", "for ", "(optional)", "review ",
            "on the ", "from the ", "go to", "click ",
        )):
            return True

        return False

    def _is_table_line(self, line: str) -> bool:
        s = line.strip()
        if not s:
            return False
        if s.startswith("|") and s.endswith("|"):
            return True
        return s.count("|") >= 2

    def _is_frontmatter_delimiter(self, line: str) -> bool:
        return line.strip() in {"---", "+++"}

    def _is_comment_line(self, line: str) -> bool:
        s = line.strip()
        return s.startswith("#") or s.startswith("//")

    def _is_jsonish_line(self, line: str) -> bool:
        s = line.strip()
        if not s:
            return False
        if s in {"{", "}", "[", "]", "},", "],", "{,", "[,"}:
            return True
        if re.match(r'^"?[A-Za-z0-9_.$:-]+"?\s*:\s*[\[{"]?.*[,}]?$', s):
            return True
        return False

    def _is_rule_like_line(self, line: str) -> bool:
        """
        Detect actual rule/config/syntax lines.
        This is intentionally stricter than earlier versions, so prose notes
        containing words like body/cookie/lowercase do not become tiny rule chunks.
        """
        s = line.strip()
        if not s:
            return False

        lower = s.lower()

        starts = [
            "secrule", "secaction", "secruleupdate", "secruleremove",
            "mainrule", "basicrule", "checkrule", "secrulesenabled",
            "learningmode", "deniedurl", "include ", "load_module ",
            "location ", "server ", "deny ", "allow ", "block ", "drop ",
            "id:", "phase:", "ctl:", "t:", "msg:", "tag:", "logdata:",
            "expression:", "statement:", "condition:", "action:", "actions:",
            "operator:", "match:", "pattern:", "regex:",
        ]
        if any(lower.startswith(p) for p in starts):
            return True

        syntax_terms = [
            "@rx", "@contains", "@streq", "@detectxss", "@detectsqli",
            "xssmatchstatement", "sqlimatchstatement", "regexmatchstatement", "bytematchstatement",
            "texttransformations", "fieldtomatch", "singleheader", "singlequeryargument",
            "allqueryarguments", "body", "jsonbody",
        ]
        if any(term in lower.replace("_", "") for term in syntax_terms):
            return True

        # Cloudflare expression examples.
        if ("http.request." in lower or "cf." in lower or "ip.src" in lower) and re.search(
            r"\b(eq|ne|contains|matches|in|starts_with|ends_with|==|!=|and|or)\b|[=!<>]=?",
            lower,
        ):
            return True

        # Naxsi score/matchzone syntax.
        if re.search(r'\b(mz:|str:|rx:|s:\$|id:\d+)\b', lower):
            return True

        # AWS WAF JSON/API fragments.
        if self._is_jsonish_line(s) and re.search(
            r"name|statement|fieldtomatch|texttransformation|xss|sqli|regex|byte|action|block|count|allow",
            lower.replace("_", ""),
        ):
            return True

        return False

    def _append_block(self, blocks: List[Dict[str, Any]], block_type: str, lines: List[str]):
        content = "\n".join(lines).strip("\n")
        if content.strip():
            blocks.append({"type": block_type, "content": content})

    def _split_into_semantic_blocks(self, text: str) -> List[Dict[str, Any]]:
        """
        Split text into blocks that reflect WAF document structure:
        headings, instruction sequences, code/rule blocks, tables, comments, and prose.
        """
        if not text or not text.strip():
            return []

        lines = text.splitlines()
        blocks: List[Dict[str, Any]] = []
        i = 0

        # YAML/TOML frontmatter in Markdown docs.
        if lines and self._is_frontmatter_delimiter(lines[0]):
            delim = lines[0].strip()
            fm = [lines[0]]
            i = 1
            while i < len(lines):
                fm.append(lines[i])
                if lines[i].strip() == delim:
                    i += 1
                    break
                i += 1
            self._append_block(blocks, "frontmatter", fm)

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped:
                i += 1
                continue

            # Fenced code blocks.
            if stripped.startswith("```") or stripped.startswith("~~~"):
                delim = stripped[:3]
                buf = [line]
                i += 1
                while i < len(lines):
                    buf.append(lines[i])
                    if lines[i].strip().startswith(delim):
                        i += 1
                        break
                    i += 1
                self._append_block(blocks, "code_fence", buf)
                continue

            # Page markers, if any were injected by extraction.
            if re.match(r"^<PAGE\s+\d+>", stripped):
                self._append_block(blocks, "page_marker", [line])
                i += 1
                continue

            # Headings.
            if self._is_doc_heading_line(line):
                self._append_block(blocks, "heading", [line])
                i += 1
                continue

            # Markdown tables.
            if self._is_table_line(line):
                buf = [line]
                i += 1
                while i < len(lines) and (self._is_table_line(lines[i]) or not lines[i].strip()):
                    if lines[i].strip():
                        buf.append(lines[i])
                    i += 1
                self._append_block(blocks, "table", buf)
                continue

            # Comments in CRS / config docs.
            if self._is_comment_line(line):
                buf = [line]
                i += 1
                while i < len(lines) and self._is_comment_line(lines[i]):
                    buf.append(lines[i])
                    i += 1
                self._append_block(blocks, "comment", buf)
                continue

            # Rule / config / JSON blocks.
            starts_json_rule = (
                self._is_jsonish_line(line)
                and i + 1 < len(lines)
                and (self._is_rule_like_line(lines[i + 1]) or self._is_jsonish_line(lines[i + 1]))
            )
            if self._is_rule_like_line(line) or starts_json_rule or line.startswith("    ") or line.startswith("\t"):
                buf = [line]
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    ns = nxt.strip()
                    if not ns:
                        # Keep a single blank only if the next line continues the same block.
                        if i + 1 < len(lines) and (
                            self._is_rule_like_line(lines[i + 1])
                            or lines[i + 1].startswith(" ")
                            or lines[i + 1].startswith("\t")
                            or self._is_jsonish_line(lines[i + 1])
                        ):
                            buf.append(nxt)
                            i += 1
                            continue
                        break
                    if (
                        self._is_rule_like_line(nxt)
                        or nxt.startswith(" ")
                        or nxt.startswith("\t")
                        or self._is_jsonish_line(nxt)
                        or ns.startswith(("&&", "||", ")", "}", "]", ",", '"', "'"))
                        or buf[-1].rstrip().endswith("\\")
                    ):
                        buf.append(nxt)
                        i += 1
                    else:
                        break
                self._append_block(blocks, "rule_block", buf)
                continue

            # Instruction / procedural sequences.
            if self._is_instruction_line(line):
                buf = [line]
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    ns = nxt.strip()
                    if not ns:
                        i += 1
                        continue
                    if (
                        self._is_instruction_line(nxt)
                        or (len(ns) < 180 and not self._is_doc_heading_line(nxt) and not self._is_rule_like_line(nxt))
                    ):
                        buf.append(nxt)
                        i += 1
                    else:
                        break
                self._append_block(blocks, "instruction_block", buf)
                continue

            # Prose paragraph. PDF extraction often emits one visual line per line,
            # so gather until a structural boundary instead of stopping at every line.
            buf = [line]
            i += 1
            while i < len(lines):
                nxt = lines[i]
                ns = nxt.strip()
                if not ns:
                    i += 1
                    if buf and buf[-1].strip():
                        break
                    continue
                if (
                    self._is_doc_heading_line(nxt)
                    or self._is_table_line(nxt)
                    or self._is_comment_line(nxt)
                    or self._is_rule_like_line(nxt)
                    or self._is_instruction_line(nxt)
                    or nxt.strip().startswith(("```", "~~~"))
                ):
                    break
                buf.append(nxt)
                i += 1

            self._append_block(blocks, "prose", buf)

        return blocks

    def _split_oversized_rule_block(self, content: str, hard_chunk_size: int) -> List[str]:
        """Split very large rule files on rule boundaries while keeping each rule intact."""
        lines = content.splitlines()
        pieces: List[str] = []
        current: List[str] = []
        current_len = 0

        def flush():
            nonlocal current, current_len
            if current:
                pieces.append("\n".join(current).strip())
            current = []
            current_len = 0

        for line in lines:
            line_len = len(line) + 1
            is_new_rule = bool(re.match(r"^\s*(SecRule|SecAction|MainRule|BasicRule)\b", line))

            if current and is_new_rule and current_len + line_len > hard_chunk_size:
                flush()

            current.append(line)
            current_len += line_len

            # If a single line is enormous, keep it intact rather than cutting regex syntax.
            if current_len > hard_chunk_size and is_new_rule:
                flush()

        flush()
        return [p for p in pieces if p.strip()]

    def _split_oversized_block(
        self,
        content: str,
        block_type: str,
        chunk_size: int,
        chunk_overlap: int,
        hard_chunk_size: int,
    ) -> List[str]:
        """Fallback splitter for oversized blocks."""
        if block_type == "rule_block":
            rule_pieces = self._split_oversized_rule_block(content, hard_chunk_size)
            if len(rule_pieces) > 1:
                return rule_pieces
            if len(content) <= hard_chunk_size:
                return [content]

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            length_function=len,
            separators=["\n\n", "\n", ". ", "; ", " ", ""],
        )
        return splitter.split_text(content)

    def _merge_tiny_chunks(self, chunks: List[Dict[str, Any]], min_chunk_size: int, chunk_size: int) -> List[Dict[str, Any]]:
        """Merge very small chunks with neighbors to avoid one-sentence references."""
        if not chunks:
            return chunks

        merged: List[Dict[str, Any]] = []
        for item in chunks:
            content = item["content"].strip()
            if not content:
                continue

            if (
                merged
                and len(content) < min_chunk_size
                and len(merged[-1]["content"]) + len(content) + 2 <= chunk_size
                and "rule_block" not in item.get("block_types", [])
            ):
                merged[-1]["content"] += "\n\n" + content
                merged[-1]["block_types"] = list(dict.fromkeys(merged[-1]["block_types"] + item["block_types"]))
            else:
                merged.append(item)

        # Second pass: merge tiny first chunk forward if possible.
        if len(merged) >= 2 and len(merged[0]["content"]) < min_chunk_size:
            if len(merged[0]["content"]) + len(merged[1]["content"]) + 2 <= chunk_size:
                merged[1]["content"] = merged[0]["content"] + "\n\n" + merged[1]["content"]
                merged[1]["block_types"] = list(dict.fromkeys(merged[0]["block_types"] + merged[1]["block_types"]))
                merged = merged[1:]

        return merged

    def _merge_blocks_structure_aware(
        self,
        blocks: List[Dict[str, Any]],
        chunk_size: int,
        chunk_overlap: int,
        min_chunk_size: int,
        hard_chunk_size: int,
    ) -> List[Dict[str, Any]]:
        """
        Merge semantic blocks into chunks while keeping headings, explanations,
        procedural steps, and syntax examples together.
        """
        chunks: List[Dict[str, Any]] = []
        current_parts: List[str] = []
        current_types: List[str] = []
        current_len = 0

        def flush():
            nonlocal current_parts, current_types, current_len
            if current_parts:
                content = "\n\n".join(part.strip("\n") for part in current_parts if part.strip())
                if content.strip():
                    chunks.append({
                        "content": content,
                        "block_types": list(dict.fromkeys(current_types)),
                    })
            current_parts = []
            current_types = []
            current_len = 0

        for block in blocks:
            block_type = block["type"]
            if block_type in {"frontmatter", "page_marker"}:
                continue

            block_content = block["content"].strip("\n")
            if not block_content.strip():
                continue

            block_len = len(block_content)

            if block_len > hard_chunk_size:
                flush()
                for sub in self._split_oversized_block(block_content, block_type, chunk_size, chunk_overlap, hard_chunk_size):
                    chunks.append({
                        "content": sub,
                        "block_types": [block_type, "oversized_split"],
                    })
                continue

            # Headings start a new semantic section once we already have useful content.
            if block_type == "heading" and current_len >= min_chunk_size:
                flush()

            projected = current_len + (2 if current_parts else 0) + block_len
            if current_parts and projected > chunk_size:
                flush()

            current_parts.append(block_content)
            current_types.append(block_type)
            current_len += (2 if current_len else 0) + block_len

            # Do not flush immediately after rule/code blocks. Keeping the preceding
            # heading and following explanation is more useful for generation.

        flush()
        chunks = self._merge_tiny_chunks(chunks, min_chunk_size=min_chunk_size, chunk_size=chunk_size)

        # Add overlap only to prose/instruction chunks. Do not prepend arbitrary tails to code/rules.
        if chunk_overlap <= 0 or len(chunks) <= 1:
            return chunks

        final_chunks: List[Dict[str, Any]] = []
        prev_tail = ""
        for item in chunks:
            content = item["content"]
            block_types = item["block_types"]
            can_overlap = not any(t in block_types for t in ("rule_block", "code_fence", "table"))
            if prev_tail and can_overlap:
                content = prev_tail + "\n\n" + content

            final_chunks.append({"content": content, "block_types": block_types})

            if can_overlap:
                tail_source = item["content"]
                prev_tail = tail_source[-chunk_overlap:] if len(tail_source) > chunk_overlap else tail_source
            else:
                prev_tail = ""

        return final_chunks

    def _get_chunk_params(self, doc: Document) -> Tuple[int, int, int, int]:
        """Return chunk_size, overlap, min_chunk_size, hard_chunk_size for a document."""
        meta = doc.metadata
        waf_type = meta.get("waf_type", "")
        file_type = meta.get("file_type", "")
        source = meta.get("source", "")

        if waf_type == "ModSecurity" and "Rules for SQL Injection and XSS" in source:
            return 3600, 150, 500, 5200
        if waf_type == "ModSecurity":
            return 2600, 180, 450, 4200
        if waf_type == "AWS" and file_type == "pdf":
            return 2400, 180, 450, 3600
        if waf_type == "AWS":
            return 2600, 180, 450, 3600
        if waf_type == "Cloudflare":
            return 2200, 160, 400, 3400
        if waf_type == "Naxsi":
            return 2200, 160, 400, 3400
        if meta.get("data_type") == "Rules":
            return 2200, 160, 400, 3400
        return 1200, 180, 300, 2200

    def _chunk_documents(self, documents: List[Document]) -> List[Document]:
        """
        Structure-aware chunking:
        - preserves rule examples / syntax blocks / JSON / config blocks
        - keeps procedural steps together
        - stores global chunk ids per file, not page-local ids
        - preserves PDF page_start/page_end metadata
        """
        grouped: Dict[str, List[Document]] = {}
        for doc in documents:
            file_key = doc.metadata.get("file_path") or doc.metadata.get("source", "unknown")
            grouped.setdefault(file_key, []).append(doc)

        file_chunks: Dict[str, List[Dict[str, Any]]] = {}

        for file_key, docs in grouped.items():
            docs.sort(key=lambda d: (d.metadata.get("page") is None, d.metadata.get("page") or 0))
            file_chunks[file_key] = []

            for doc in docs:
                try:
                    text = self._normalize_document_text(
                        doc.page_content or "",
                        file_type=doc.metadata.get("file_type", ""),
                        source=doc.metadata.get("source", ""),
                    )
                    if not text.strip():
                        continue

                    chunk_size, chunk_overlap, min_chunk_size, hard_chunk_size = self._get_chunk_params(doc)
                    blocks = self._split_into_semantic_blocks(text)
                    merged_items = self._merge_blocks_structure_aware(
                        blocks,
                        chunk_size=chunk_size,
                        chunk_overlap=chunk_overlap,
                        min_chunk_size=min_chunk_size,
                        hard_chunk_size=hard_chunk_size,
                    )

                    page = doc.metadata.get("page")
                    for item in merged_items:
                        file_chunks[file_key].append({
                            "content": item["content"],
                            "block_types": item.get("block_types", []),
                            "base_metadata": dict(doc.metadata),
                            "page_start": page,
                            "page_end": page,
                        })

                except Exception as e:
                    print(f"Warning: Failed to chunk {doc.metadata.get('source')}: {str(e)}")

            # Merge small adjacent page chunks for PDFs when it keeps section context together.
            compacted: List[Dict[str, Any]] = []
            for item in file_chunks[file_key]:
                if (
                    compacted
                    and item["base_metadata"].get("file_type") == "pdf"
                    and len(compacted[-1]["content"]) + len(item["content"]) + 2 <= 2400
                    and not any(t in item.get("block_types", []) for t in ("rule_block", "code_fence", "table"))
                    and not any(t in compacted[-1].get("block_types", []) for t in ("rule_block", "code_fence", "table"))
                ):
                    compacted[-1]["content"] += "\n\n" + item["content"]
                    compacted[-1]["block_types"] = list(dict.fromkeys(compacted[-1]["block_types"] + item["block_types"]))
                    compacted[-1]["page_end"] = item.get("page_end")
                else:
                    compacted.append(item)
            file_chunks[file_key] = compacted

        chunks: List[Document] = []
        for file_key, items in file_chunks.items():
            total = len(items)
            for idx, item in enumerate(items):
                meta = dict(item["base_metadata"])
                meta.update({
                    "chunk_id": idx,
                    "file_chunk_index": idx,
                    "total_chunks": total,
                    "chunking_strategy": "structure_aware_v2",
                    "block_types": item.get("block_types", []),
                    "page_start": item.get("page_start"),
                    "page_end": item.get("page_end"),
                })
                chunks.append(Document(page_content=item["content"], metadata=meta))

        return chunks

    # ---------------------------------------------------------------------
    # Retrieval helpers
    # ---------------------------------------------------------------------

    def _normalize_attack_type(self, attack_type: Optional[str]) -> str:
        """
        Normalize attack type provided by caller.
        This does not infer from payloads; it only maps known labels from main.py/UI.
        """
        if not attack_type:
            return "Unknown"

        s = str(attack_type).strip().lower()
        s = s.replace("-", "_").replace(" ", "_")

        if "xss" in s or "cross_site" in s or "cross-site" in s:
            return "XSS"
        if "sqli" in s or "sql_injection" in s or "sqlinjection" in s or s == "sql":
            return "SQLI"
        if "lfi" in s or "local_file" in s:
            return "LFI"
        if "rfi" in s or "remote_file" in s:
            return "RFI"
        if "ssrf" in s:
            return "SSRF"
        if "rce" in s or "command_injection" in s or "cmdi" in s:
            return "RCE"

        return str(attack_type).strip() or "Unknown"

    def _attack_terms(self, attack_type: str) -> List[str]:
        t = self._normalize_attack_type(attack_type)
        if t == "XSS":
            return ["XSS", "cross-site scripting", "script", "onerror", "onload", "javascript", "xss match statement"]
        if t == "SQLI":
            return ["SQL injection", "SQLi", "union select", "sqli match statement", "database"]
        if t == "SSRF":
            return ["SSRF", "server-side request forgery", "metadata", "169.254.169.254"]
        return [t]

    def _extract_payload_signals(self, payloads: list, max_signals: int = 10) -> List[str]:
        """Extract high-value lexical signals from payloads for query expansion."""
        text = " ".join(str(p) for p in payloads).lower()

        candidates = [
            "script", "alert", "onerror", "onload", "onclick", "iframe", "svg",
            "img", "src", "href", "javascript:", "data:", "document.cookie",
            "eval", "fromcharcode", "settimeout",
            "union", "select", "sleep", "benchmark", "or 1=1", "information_schema",
            "../", "..\\", "%3c", "%3e", "%27", "%22", "url_encode",
            "double_url", "whitespace", "case_random",
        ]

        found = []
        for c in candidates:
            if c in text and c not in found:
                found.append(c)

        extra = re.findall(r"[a-zA-Z_]{4,}|\%\w{2}", text)
        for token in extra:
            if token not in found and len(found) < max_signals:
                found.append(token)

        return found[:max_signals]

    def _generate_query_variants(self, attack_type: str, waf_name: Optional[str], bypassed_payloads: list) -> List[str]:
        """Generate retrieval queries optimized for rule-authoring evidence."""
        waf = waf_name or "WAF"
        normalized_attack = self._normalize_attack_type(attack_type)
        attack_terms = " ".join(self._attack_terms(normalized_attack)[:3])
        signals = self._extract_payload_signals(bypassed_payloads)
        signal_str = " ".join(signals[:6]) if signals else attack_terms

        queries = [
            f"{waf} {normalized_attack} rule syntax statement example fields action transformation",
            f"{waf} {attack_terms} detection rule example request component text transformation",
            f"{waf} rule detect {signal_str}",
            f"{normalized_attack} bypass normalization decoding canonicalization lowercase url decode html entity rule",
            f"{waf} inspect query string body headers cookies uri {normalized_attack} rule statement",
        ]

        if waf == "AWS":
            if normalized_attack == "XSS":
                queries.extend([
                    "AWS WAF XSS match statement FieldToMatch TextTransformations JSON example",
                    "AWS WAF Contains XSS injection attacks custom rule request components",
                ])
            elif normalized_attack == "SQLI":
                queries.extend([
                    "AWS WAF SQL injection match statement FieldToMatch TextTransformations JSON example",
                    "AWS WAF Contains SQL injection attacks custom rule request components",
                ])
            queries.append("AWS WAF regex match statement text transformations field to match")

        if waf == "Cloudflare":
            queries.extend([
                f"Cloudflare Ruleset Engine expression {normalized_attack} http.request.uri.query body contains matches",
                "Cloudflare custom rule expression fields operators functions lower matches contains",
            ])

        if waf == "ModSecurity":
            queries.extend([
                f"ModSecurity SecRule {normalized_attack} variables operators transformations actions example",
                "OWASP CRS XSS SQL injection SecRule ARGS REQUEST_BODY REQUEST_HEADERS",
            ])

        if waf == "Naxsi":
            queries.extend([
                f"Naxsi MainRule BasicRule {normalized_attack} mz ARGS URL BODY score CheckRule example",
                "Naxsi rule syntax MainRule BasicRule str rx mz msg score",
            ])

        deduped = []
        seen = set()
        for q in queries:
            key = q.strip().lower()
            if key not in seen:
                seen.add(key)
                deduped.append(q)

        return deduped

    def _extract_waf_name(self, waf_name: Any) -> Optional[str]:
        """Extract WAF name from input and map to internal WAF_type."""
        if not waf_name:
            return None

        waf_mapping = {
            "cloudflare": "Cloudflare",
            "cloud flare": "Cloudflare",
            "modsecurity": "ModSecurity",
            "mod_security": "ModSecurity",
            "modsec": "ModSecurity",
            "aws waf": "AWS",
            "aws": "AWS",
            "amazon": "AWS",
            "elastic load balancer": "AWS",
            "alb": "AWS",
            "elb": "AWS",
            "naxsi": "Naxsi",
        }

        normalized = str(waf_name).lower()
        for key, value in waf_mapping.items():
            if key in normalized:
                return value

        return None

    def _score_rule_usefulness(
        self,
        doc: Document,
        waf_name: Optional[str],
        attack_type: str,
        payload_signals: List[str],
    ) -> float:
        """Heuristic usefulness score before cross-encoder reranking."""
        text = doc.page_content.lower()
        meta = doc.metadata
        score = 0.0

        if meta.get("data_type") == "Rules":
            score += 4.0

        if waf_name and meta.get("waf_type") == waf_name:
            score += 5.0

        block_types = meta.get("block_types", [])
        block_weights = {
            "rule_block": 3.0,
            "code_fence": 2.0,
            "instruction_block": 2.2,
            "table": 1.3,
            "heading": 0.6,
            "prose": 0.2,
        }
        for bt, w in block_weights.items():
            if bt in block_types:
                score += w

        rule_terms = [
            "rule", "syntax", "operator", "transform", "transformation",
            "match", "expression", "regex", "example", "field", "fieldtomatch",
            "request component", "args", "header", "body", "cookie", "uri",
            "query string", "action", "deny", "block", "count", "allow",
            "condition", "statement", "filter", "inspect", "text transformations",
            "secrule", "mainrule", "basicrule", "checkrule",
        ]
        for term in rule_terms:
            if term in text:
                score += 0.35

        for term in self._attack_terms(attack_type):
            if term.lower() in text:
                score += 0.9

        for signal in payload_signals:
            if signal and signal.lower() in text:
                score += 1.2

        # Penalize tiny prose chunks that are rarely sufficient for rule synthesis.
        if len(doc.page_content.strip()) < 220 and not any(t in block_types for t in ("rule_block", "code_fence")):
            score -= 1.2

        return score

    def _ensure_chunk_lookup(self):
        """Build a lookup of all chunks from the current vector store docstore."""
        if self.chunk_lookup is not None:
            return

        self.chunk_lookup = {}
        if not self.vector_store:
            return

        store = getattr(self.vector_store, "docstore", None)
        raw_docs = getattr(store, "_dict", {}) if store is not None else {}
        for doc in raw_docs.values():
            meta = getattr(doc, "metadata", {}) or {}
            file_key = meta.get("file_path") or meta.get("doc_rel_path") or meta.get("source")
            chunk_id = meta.get("chunk_id")
            if file_key is None or chunk_id is None:
                continue
            self.chunk_lookup[(file_key, chunk_id)] = doc

    def _expand_neighbor_chunks(self, docs: List[Document], window: int = 1, max_added: int = 8) -> List[Document]:
        """
        Add adjacent chunks from the same file using the full FAISS docstore.
        This works even when the adjacent chunks were not returned by similarity search.
        """
        self._ensure_chunk_lookup()

        selected_keys = set()
        expanded = []

        for d in docs:
            meta = d.metadata
            file_key = meta.get("file_path") or meta.get("doc_rel_path") or meta.get("source")
            key = (file_key, meta.get("chunk_id"))
            selected_keys.add(key)
            expanded.append(d)

        added = 0
        for d in list(docs):
            meta = d.metadata
            file_key = meta.get("file_path") or meta.get("doc_rel_path") or meta.get("source")
            chunk_id = meta.get("chunk_id")

            if not isinstance(chunk_id, int):
                continue

            for offset in range(1, window + 1):
                for neighbor_id in (chunk_id - offset, chunk_id + offset):
                    key = (file_key, neighbor_id)
                    if key in selected_keys:
                        continue
                    neighbor = self.chunk_lookup.get(key) if self.chunk_lookup else None
                    if neighbor is not None:
                        expanded.append(neighbor)
                        selected_keys.add(key)
                        added += 1
                        if added >= max_added:
                            return expanded

        return expanded

    def _build_rule_context(self, reranked_results: List[Tuple[Document, float]]) -> str:
        """Build structured context for LLM prompt."""
        blocks = []

        for i, (doc, score) in enumerate(reranked_results, start=1):
            meta = doc.metadata
            source = meta.get("source", "Unknown")
            data_type = meta.get("data_type", "Unknown")
            waf_type = meta.get("waf_type", "None")
            chunk_id = meta.get("chunk_id", -1)
            total_chunks = meta.get("total_chunks", -1)
            block_types = meta.get("block_types", [])
            page_start = meta.get("page_start")
            page_end = meta.get("page_end")
            page_info = ""
            if page_start:
                page_info = f"\nPages: {page_start}" if page_start == page_end else f"\nPages: {page_start}-{page_end}"

            blocks.append(
                f"""[Reference {i}]
Source: {source}
Type: {data_type}
WAF: {waf_type}
Chunk: {chunk_id}/{total_chunks}{page_info}
Block types: {block_types}
Raw rerank score: {score:.3f}

Useful excerpt:
{doc.page_content.strip()}
"""
            )

        return "\n---\n".join(blocks)

    def get_relevant_context(
        self,
        attack_type: str,
        waf_name: str,
        bypassed_payloads: list,
        initial_k: int = 16,
        final_k: int = 5,
        filter_rules_only: bool = True,
    ) -> Dict[str, Any]:
        """
        Retrieve relevant context using multi-query retrieval, WAF filtering,
        heuristic usefulness scoring, neighbor expansion, and cross-encoder reranking.
        """
        result = {
            "rag_enabled": self.enable_rag,
            "num_queries": 0,
            "num_docs_all": 0,
            "num_docs_filtered": 0,
            "num_docs_preselected": 0,
            "sources": [],
            "context": "",
            "queries": [],
            "score_note": "Cross-encoder scores are raw logits; negative values are normal. Use rank/order, not absolute sign.",
        }

        if not self.enable_rag or self.retriever is None or self.reranker is None:
            return result

        try:
            normalized_attack_type = self._normalize_attack_type(attack_type)
            mapped_waf_name = self._extract_waf_name(waf_name)
            payload_signals = self._extract_payload_signals(bypassed_payloads)
            queries = self._generate_query_variants(normalized_attack_type, mapped_waf_name, bypassed_payloads)

            result["attack_type_input"] = attack_type
            result["normalized_attack_type"] = normalized_attack_type
            result["num_queries"] = len(queries)
            result["queries"] = queries

            print(f"Generated {len(queries)} query variants for retrieval")
            for query in queries:
                print(f"\t- {query}")

            all_retrieved_docs: List[Document] = []
            seen_keys = set()

            self.retriever.search_kwargs["k"] = initial_k

            for query in queries:
                docs = self.retriever.invoke(query)
                print(f"Retrieved {len(docs)} documents for query: {query}")

                for doc in docs:
                    meta = doc.metadata or {}
                    dedupe_key = (
                        meta.get("file_path") or meta.get("doc_rel_path") or meta.get("source"),
                        meta.get("chunk_id"),
                        hash(doc.page_content[:500]),
                    )
                    if dedupe_key not in seen_keys:
                        seen_keys.add(dedupe_key)
                        all_retrieved_docs.append(doc)

            result["num_docs_all"] = len(all_retrieved_docs)

            if mapped_waf_name:
                print(f"WAF detected: {mapped_waf_name}")
                all_retrieved_docs = [
                    doc for doc in all_retrieved_docs
                    if doc.metadata.get("waf_type") in [mapped_waf_name, "None"]
                ]

            # Do not hard-truncate to final_k here. Keep enough candidates for rerank.
            scored_docs = []
            for doc in all_retrieved_docs:
                utility_score = self._score_rule_usefulness(doc, mapped_waf_name, normalized_attack_type, payload_signals)
                scored_docs.append((doc, utility_score))

            scored_docs.sort(key=lambda x: x[1], reverse=True)

            if filter_rules_only:
                candidate_limit = max(final_k * 10, initial_k * 3, 30)
            else:
                candidate_limit = max(final_k * 8, initial_k * 2, 24)

            filtered_docs = [doc for doc, _ in scored_docs[:candidate_limit]]
            result["num_docs_filtered"] = len(filtered_docs)

            preselected_limit = max(final_k * 6, 20)
            preselected_docs = filtered_docs[:preselected_limit]
            preselected_docs = self._expand_neighbor_chunks(
                preselected_docs,
                window=1,
                max_added=max(8, final_k * 2),
            )
            result["num_docs_preselected"] = len(preselected_docs)

            primary_query = queries[0]
            if payload_signals:
                primary_query = primary_query + " " + " ".join(payload_signals[:6])

            reranked_results = self.reranker.rerank(primary_query, preselected_docs, top_k=final_k)
            context = self._build_rule_context(reranked_results)

            raw_scores = [score for _, score in reranked_results]
            min_s = min(raw_scores) if raw_scores else 0.0
            max_s = max(raw_scores) if raw_scores else 0.0

            sources = []
            for rank, (doc, score) in enumerate(reranked_results, start=1):
                if max_s > min_s:
                    display_score = (score - min_s) / (max_s - min_s)
                else:
                    display_score = 1.0 if raw_scores else 0.0

                sources.append({
                    "rank": rank,
                    "source": doc.metadata.get("source", "Unknown"),
                    "data_type": doc.metadata.get("data_type", "Unknown"),
                    "waf_type": doc.metadata.get("waf_type", "None"),
                    "chunk_id": doc.metadata.get("chunk_id", -1),
                    "total_chunks": doc.metadata.get("total_chunks", -1),
                    "page_start": doc.metadata.get("page_start"),
                    "page_end": doc.metadata.get("page_end"),
                    "block_types": doc.metadata.get("block_types", []),
                    "rerank_score_raw": f"{float(score):.3f}",
                    "relevance_score_display": f"{display_score:.3f}",
                    # Backward-compatible field; raw cross-encoder score.
                    "relevance_score": f"{float(score):.3f}",
                    "content": doc.page_content,
                })

            result["context"] = context
            result["sources"] = sources
            result["waf_filtered"] = bool(mapped_waf_name)
            result["mapped_waf_name"] = mapped_waf_name
            return result

        except Exception as e:
            print(f"Error: Context retrieval failed: {str(e)}")
            result["error"] = str(e)
            return result

    def enhance_defense_prompt(
        self,
        waf_name: str,
        bypassed_payloads: list,
        bypassed_instructions: list,
        base_user_prompt: str,
        attack_type: Optional[str] = None,
        filter_rules_only: bool = True,
    ) -> Dict[str, Any]:
        """
        Enhance defense generation prompt with RAG context.

        Prefer passing attack_type directly from the caller/main.py. Payload-based
        detection is retained only as a fallback for backward compatibility.
        """
        if attack_type:
            normalized_attack_type = self._normalize_attack_type(attack_type)
            attack_type_source = "caller"
        else:
            normalized_attack_type = self._detect_attack_type(bypassed_payloads)
            attack_type_source = "payload_fallback"

        rag_result = self.get_relevant_context(
            attack_type=normalized_attack_type,
            waf_name=waf_name,
            bypassed_payloads=bypassed_payloads,
            filter_rules_only=filter_rules_only,
        )

        if not rag_result.get("context"):
            return {
                "enhanced_prompt": base_user_prompt,
                "rag_context": "",
                "sources": [],
                "rag_used": False,
                "attack_type": normalized_attack_type,
                "attack_type_source": attack_type_source,
            }

        enhanced_prompt = f"""{base_user_prompt}

---
KNOWLEDGE BASE REFERENCES FOR RULE GENERATION

{rag_result["context"]}

---
Use the references above as implementation evidence for writing WAF rules.

Requirements:
1. Prioritize excerpts that contain WAF-specific syntax, fields, operators, transformations, actions, procedural steps, or concrete examples.
2. Prefer excerpts that match the observed bypass payload patterns or their normalized forms.
3. Ignore references that only describe the attack generally but do not help write a rule.
4. For each generated rule, explain which reference excerpt influenced:
   - selected fields / request components
   - match condition / regex / expression / statement
   - transformation / normalization
   - action
5. Do not produce generic mitigation advice unless it directly supports rule construction.
6. Include expected false positives and tuning notes.
7. If the references do not contain enough WAF-specific syntax, state that explicitly and fall back to a conservative rule design.

Return output in this structure:
- Rule objective
- Proposed rule
- Why this rule matches the bypass
- Which reference excerpts were used
- Expected false positives / tuning notes
"""

        return {
            "enhanced_prompt": enhanced_prompt,
            "rag_context": rag_result["context"],
            "sources": rag_result["sources"],
            "rag_used": True,
            "num_docs": len(rag_result.get("sources", [])),
            "num_queries": rag_result.get("num_queries", 0),
            "waf_filtered": rag_result.get("waf_filtered", False),
            "mapped_waf_name": rag_result.get("mapped_waf_name"),
            "attack_type": normalized_attack_type,
            "attack_type_source": attack_type_source,
            "queries": rag_result.get("queries", []),
        }

    def _detect_attack_type(self, payloads: list) -> str:
        """Fallback detector only. Prefer caller-provided attack_type."""
        payload_str = " ".join(str(p) for p in payloads).lower()

        if any(keyword in payload_str for keyword in ["script", "onerror", "onload", "alert", "xss", "svg", "iframe"]):
            return "XSS"
        if any(keyword in payload_str for keyword in ["union", "select", "or 1=1", "' or", '" or', "sql", "sleep", "benchmark"]):
            return "SQLI"
        return "Unknown"

    def force_rebuild(self):
        """Force rebuild vector store."""
        print("\nForce rebuilding vector store...")
        self._build_vector_store()
        print("Rebuild complete\n")


# Singleton instance
_rag_service_instance = None


def get_rag_service(
    docs_folder: str = "./docs/",
    vector_store_path: str = "./vector_store/",
    enable_rag: bool = True,
    force_rebuild: bool = False,
) -> RAGDefenseService:
    """Get or create RAG service singleton."""
    global _rag_service_instance

    if _rag_service_instance is None or force_rebuild:
        _rag_service_instance = RAGDefenseService(
            docs_folder=docs_folder,
            vector_store_path=vector_store_path,
            enable_rag=enable_rag,
            force_rebuild=force_rebuild,
        )

    return _rag_service_instance


def get_relevant_context(
    attack_type: str,
    waf_name: str,
    bypassed_payloads: list,
    initial_k: int = 16,
    final_k: int = 5,
    filter_rules_only: bool = True,
) -> Dict[str, Any]:
    return get_rag_service().get_relevant_context(
        attack_type=attack_type,
        waf_name=waf_name,
        bypassed_payloads=bypassed_payloads,
        initial_k=initial_k,
        final_k=final_k,
        filter_rules_only=filter_rules_only,
    )
