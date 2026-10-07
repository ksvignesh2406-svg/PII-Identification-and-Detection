from docx import Document
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine


# -----------------------------
# Presidio setup
# -----------------------------
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()


# -----------------------------
# Redact one paragraph
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

    # Process from the end so earlier positions don't change
    results = sorted(results, key=lambda x: x.start, reverse=True)

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
# Process the whole DOCX
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
# Run
# -----------------------------
input_file = "uploads/pii_redaction_test.docx"
output_file = "outputs/redacted1.docx"

process_docx(input_file, output_file)

print("Redaction complete!")
print("Output:", output_file)