// Standalone Ghidra script to run Anti-Debug Seeker analysis.
// This script utilizes the core analysis engine shared with the plugin.
// @author Your Name/Handle
// @category Analysis.AntiDebug
// @keybinding
// @menupath Analysis.Anti-Debug Seeker.Run Script Analysis
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg; // Use Ghidra's logging
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

// Import the core classes
import antidebugseeker.AntiDebugConfig;
import antidebugseeker.AntiDebugAnalysisCore;

import java.io.IOException;

public class AntiDebugSeeker extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program open. Please open a program before running the script.");
            Msg.showError(this, null, "Script Error", "No program open.");
            return;
        }

        println("Starting Anti-Debug Seeker Script for: " + currentProgram.getName());
        println("Loading configuration...");

        AntiDebugConfig config;
        try {
            // Load configuration using the shared core logic
            // This assumes the config/json files are in the expected module 'data' directory
            config = AntiDebugConfig.loadConfig();
            println("Configuration loaded successfully.");
            // Log loaded rule counts (optional)
            println(String.format(" - API Rules: %d (%s)", config.getApiCalls().size(), config.isAnalyzeApiCallsEnabled() ? "Enabled" : "Disabled"));
            println(String.format(" - Keyword Group Rules: %d (%s)", config.getKeywordGroups().size(), config.isAnalyzeKeywordsEnabled() ? "Enabled" : "Disabled"));
            println(String.format(" - Instruction Rules: %d (%s)", config.getInstructions().size(), config.isAnalyzeInstructionsEnabled() ? "Enabled" : "Disabled"));
            println(String.format(" - Byte Sequence Rules: %d (%s)", config.getByteSequences().size(), config.isAnalyzeBytesEnabled() ? "Enabled" : "Disabled"));
            println(String.format(" - CSV Output: %s %s", config.isCsvOutputEnabled() ? "Enabled" : "Disabled", config.isCsvOutputEnabled() && config.getCsvOutputPath() != null ? "("+config.getCsvOutputPath()+")" : ""));

             // Check if any analysis is actually enabled
            if (!config.isAnalyzeApiCallsEnabled() && !config.isAnalyzeKeywordsEnabled() &&
                !config.isAnalyzeInstructionsEnabled() && !config.isAnalyzeBytesEnabled()) {
                println("\nWarning: All analysis types are disabled in the configuration. No analysis performed.");
                Msg.showWarn(this, null, "Analysis Skipped", "All analysis types are disabled in the configuration.");
                return; // Stop if nothing to do
            }

        } catch (IOException | NotFoundException e) {
            printerr("Failed to load configuration files: " + e.getMessage());
            printerr("Ensure the AntiDebugSeeker module is installed correctly and config/JSON files exist in its 'data' directory.");
            Msg.showError(this, null, "Configuration Error", "Failed to load configuration files: " + e.getMessage());
            e.printStackTrace(getPrintWriter(err)); // Print stack trace to console
            return; // Stop script
        } catch (Exception e) {
             printerr("An unexpected error occurred while loading configuration: " + e.getMessage());
             Msg.showError(this, null, "Configuration Error", "An unexpected error occurred while loading configuration: " + e.getMessage());
             e.printStackTrace(getPrintWriter(err));
             return; // Stop script
        }

        // Run analysis within a transaction
        int transactionID = currentProgram.startTransaction("Anti-Debug Seeker Script Analysis");
        boolean success = false;
        try {
            println("\nStarting analysis core...");
            // Use println as the logger for script output
            // Pass the script's monitor instance
            AntiDebugAnalysisCore.analyzeProgram(currentProgram, config, this::println, monitor);

            // If analyzeProgram completes without exception, mark as success
            success = true;
            println("\nScript analysis finished successfully!");
            Msg.showInfo(this, null, "Analysis Complete", "Anti-Debug Seeker script finished.\nCheck console output and Bookmarks panel for results.");

        } catch (CancelledException e) {
            println("\nAnalysis cancelled by user.");
            // Transaction will be rolled back (success remains false)
        } catch (Exception e) {
            printerr("\nAn error occurred during analysis: " + e.getMessage());
            Msg.showError(this, null, "Analysis Error", "An error occurred during analysis: " + e.getMessage());
            e.printStackTrace(getPrintWriter(err)); // Print stack trace to console
            // Transaction will be rolled back (success remains false)
        } finally {
            // End the transaction, committing only if analysis completed successfully
            currentProgram.endTransaction(transactionID, success);
            println("Analysis transaction finished (Committed: " + success + ").");
        }
    }
}
