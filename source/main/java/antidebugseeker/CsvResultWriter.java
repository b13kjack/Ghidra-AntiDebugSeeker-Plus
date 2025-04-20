package antidebugseeker;

import ghidra.util.Msg;
import antidebugseeker.AntiDebugAnalysisCore.Finding; // Import the inner Finding record
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Utility class for writing analysis results (Findings) to a CSV file.
 * Corrected version uses UTF-8 encoding.
 */
public class CsvResultWriter {

    // Define the CSV header columns - must match the order in formatCsvRow
    private static final String CSV_HEADER = "Address,Type,RuleName,Severity,FunctionContext,Description";

    /** Private constructor to prevent instantiation. */
    private CsvResultWriter() {}

    /**
     * Writes the list of findings to a CSV file using UTF-8 encoding.
     * Creates parent directories if they don't exist.
     * Overwrites the file if it already exists.
     *
     * @param outputPath The path to the output CSV file. Must not be null.
     * @param findings The list of findings to write. Must not be null.
     * @throws IOException If an I/O error occurs during directory creation or file writing.
     * @throws NullPointerException If outputPath or findings is null.
     */
    public static void writeResults(Path outputPath, List<Finding> findings) throws IOException {
        Objects.requireNonNull(outputPath, "CSV output path cannot be null");
        Objects.requireNonNull(findings, "Findings list cannot be null");

        // Ensure parent directories exist before trying to write the file
        Path parentDir = outputPath.getParent();
        if (parentDir != null) { // Root directories (e.g., C:\) might have null parent
            try {
                // Create directories only if they don't already exist
                Files.createDirectories(parentDir);
                Msg.debug(CsvResultWriter.class, "Ensured directory exists for CSV output: " + parentDir);
            } catch (IOException e) {
                Msg.error(CsvResultWriter.class, "Failed to create directories for CSV output path: " + parentDir, e);
                throw e; // Re-throw the exception to signal failure
            }
        }

        // Use try-with-resources for automatic closing of the writer
        // ** FIX: Specify UTF-8 encoding **
        try (PrintWriter writer = new PrintWriter(new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outputPath.toFile()), StandardCharsets.UTF_8)))) {

            // Write Header row
            writer.println(CSV_HEADER);

            // Write Data Rows for each finding
            for (Finding finding : findings) {
                if (finding != null) { // Basic null check for safety
                    writer.println(formatCsvRow(finding));
                }
            }
            writer.flush(); // Ensure all buffered data is written to the file
            Msg.info(CsvResultWriter.class, "Successfully wrote " + findings.size() + " findings to " + outputPath + " (UTF-8)");
        } catch (IOException e) {
             Msg.error(CsvResultWriter.class, "Error writing CSV results to " + outputPath, e);
             throw e; // Re-throw to indicate failure
        }
    }

    /**
     * Formats a Finding object into a single, properly quoted CSV row string.
     *
     * @param finding The Finding object to format.
     * @return A string representing the CSV row.
     */
    private static String formatCsvRow(Finding finding) {
        // Ensure the order matches the CSV_HEADER constant
        return String.join(",",
            quoteCsv(finding.address().toString()), // Address (usually safe, but quote anyway)
            quoteCsv(finding.type()),               // Type (e.g., "API", "Keyword Group")
            quoteCsv(finding.ruleName()),           // Rule Name (e.g., API name, group name)
            quoteCsv(finding.severity().name()),    // Severity Enum name (e.g., "MEDIUM", "HIGH")
            quoteCsv(finding.functionContext()),    // Function Name or "N/A"
            quoteCsv(finding.description())         // Description text
        );
    }

    /**
     * Quotes a string value for safe inclusion in a CSV file.
     * Handles nulls, commas, double quotes, and newlines within the string.
     *
     * @param value The string to quote.
     * @return The CSV-safe quoted string.
     */
    private static String quoteCsv(String value) {
        if (value == null) {
            return "\"\""; // Represent null as an empty quoted string
        }

        // Replace existing double quotes with two double quotes
        String escapedValue = value.replace("\"", "\"\"");

        // If the original value contained a comma, double quote, or newline/carriage return,
        // then enclose the escaped value in double quotes.
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + escapedValue + "\"";
        }

        // If no special characters were present, return the (potentially escaped) value as is.
        // Note: Even if only quotes were escaped, it's often safer to quote the whole field.
        // Let's always quote if escaping happened or special chars were present.
        if (escapedValue.length() != value.length()) { // Quotes were escaped
             return "\"" + escapedValue + "\"";
        }

        // Otherwise, no quoting needed (though quoting everything is also valid CSV)
        // For consistency and maximum safety, always quoting might be preferred,
        // but this implementation only quotes when necessary or when escapes occurred.
        return value;
    }
}
