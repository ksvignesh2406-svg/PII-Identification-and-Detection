import sys
import argparse
from pathlib import Path
from docx import Document
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

# -----------------------------
# Base Directories
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUTS_DIR = BASE_DIR / "outputs"

# -----------------------------
# Presidio setup
# -----------------------------
try:
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
    })
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
except Exception:
    analyzer = AnalyzerEngine()

anonymizer = AnonymizerEngine()


# -----------------------------
# Redact one paragraph in DOCX (Preserving styles & runs)
# -----------------------------
def redact_paragraph(paragraph):

    # Get all text while keeping the runs
    full_text = "".join(run.text for run in paragraph.runs)

    if not full_text:
        return

    # Detect PII
    results = analyzer.analyze(
        text=full_text,
        language="en"
    )

    if not results:
        return

    # Filter out overlapping entities (prefer higher confidence score, then longer span)
    filtered_results = []
    for res in sorted(results, key=lambda x: (x.score, x.end - x.start), reverse=True):
        if not any(res.start < kept.end and res.end > kept.start for kept in filtered_results):
            filtered_results.append(res)

    # Process from the end so earlier positions don't change
    results = sorted(filtered_results, key=lambda x: x.start, reverse=True)

    for result in results:

        replacement = f"<{result.entity_type}>"

        # Find which runs contain the PII
        current_position = 0

        for run in paragraph.runs:

            run_start = current_position
            run_end = current_position + len(run.text)

            current_position = run_end

            # No overlap with this run
            if result.end <= run_start or result.start >= run_end:
                continue

            # PII is completely inside this run
            if result.start >= run_start and result.end <= run_end:

                start_in_run = result.start - run_start
                end_in_run = result.end - run_start

                run.text = (
                    run.text[:start_in_run]
                    + replacement
                    + run.text[end_in_run:]
                )

                break

            # PII spans multiple runs
            else:

                # First run containing the PII
                if result.start >= run_start and result.start < run_end:

                    start_in_run = result.start - run_start

                    run.text = (
                        run.text[:start_in_run]
                        + replacement
                    )

                # Following runs containing the PII
                elif result.start < run_start < result.end:

                    if result.end >= run_end:
                        run.text = ""
                    else:
                        end_in_run = result.end - run_start
                        run.text = run.text[end_in_run:]


# -----------------------------
# Process DOCX Files
# -----------------------------
def process_docx(input_file, output_file):

    doc = Document(input_file)

    # Normal paragraphs
    for paragraph in doc.paragraphs:
        redact_paragraph(paragraph)

    # Tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    redact_paragraph(paragraph)

    # Save
    doc.save(output_file)


# -----------------------------
# Process Plain Text Files (.txt, .md, etc.)
# -----------------------------
def process_txt(input_file, output_file):

    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    results = analyzer.analyze(text=text, language="en")
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(anonymized.text)


# -----------------------------
# Unified File Processor
# -----------------------------
def process_file(input_file: Path, output_file: Path = None):

    input_path = Path(input_file).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    if output_file is None:
        output_path = OUTPUTS_DIR / f"redacted_{input_path.name}"
    else:
        output_path = Path(output_file).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\nProcessing: {input_path.name}")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")

    suffix = input_path.suffix.lower()
    if suffix == ".docx":
        process_docx(str(input_path), str(output_path))
    else:
        process_txt(input_path, output_path)

    print(f"Redaction complete for {input_path.name} -> {output_path}")
    return output_path


# -----------------------------
# Interactive Selection Helper
# -----------------------------
def select_file_interactive(files):

    print("\nAvailable sample files in uploads:")
    for idx, f in enumerate(files, 1):
        print(f"  [{idx}] {f.name}")
    print(f"  [a] Process ALL files")

    try:
        choice = input(f"\nSelect a file [1-{len(files)}] or 'a' (default [1]): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if not choice:
        choice = "1"

    if choice.lower() in ("a", "all"):
        return files

    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            return [files[idx]]
        else:
            print(f"Selection out of range. Defaulting to [1] {files[0].name}")
            return [files[0]]

    # Search by partial filename
    matched = [f for f in files if choice.lower() in f.name.lower()]
    if matched:
        return [matched[0]]

    print(f"No match for '{choice}'. Defaulting to [1] {files[0].name}")
    return [files[0]]


# -----------------------------
# Main Runner
# -----------------------------
def main():

    parser = argparse.ArgumentParser(
        description="PII Identification and Detection - Redact sensitive data from Word (.docx) and text files"
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Filename in uploads folder or full path to input document (e.g. sample_unredacted_pii.txt)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Custom output file path"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all sample files in the uploads directory"
    )

    args = parser.parse_args()

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    available_files = sorted([f for f in UPLOADS_DIR.iterdir() if f.is_file()])

    if not available_files and not args.file:
        print(f"No files found in {UPLOADS_DIR}. Please place files there first.")
        return

    # Determine target files
    if args.all:
        target_files = available_files
    elif args.file:
        file_path = Path(args.file)
        if file_path.exists():
            target_files = [file_path]
        elif (UPLOADS_DIR / args.file).exists():
            target_files = [UPLOADS_DIR / args.file]
        else:
            matched = [f for f in available_files if args.file.lower() in f.name.lower()]
            if matched:
                target_files = [matched[0]]
            else:
                raise FileNotFoundError(f"Could not find '{args.file}' in uploads folder.")
    else:
        if sys.stdin.isatty():
            target_files = select_file_interactive(available_files)
        else:
            target_files = [available_files[0]]

    for f in target_files:
        custom_out = args.output if (len(target_files) == 1 and args.output) else None
        process_file(f, custom_out)


if __name__ == "__main__":
    main()