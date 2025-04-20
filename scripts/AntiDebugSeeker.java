// Standalone Ghidra script to run Anti-Debug Seeker analysis.
// This script utilizes the core analysis engine shared with the plugin
// but prompts the user for configuration files.
// @author b13kjack (incorporating original work by takatake-code/LAC)
// @category Analysis.AntiDebug
// @keybinding
// @menupath Analysis.Anti-Debug Seeker.Run Standalone Script Analysis
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// Import the core classes
import antidebugseeker.AntiDebugConfig;
import antidebugseeker.AntiDebugAnalysisCore;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;
import java.io.IOException;

public class AntiDebugSeeker extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Error: No program open. Please open a program before running the script.");
            Msg.showError(this, null, "Script Error", "No program open.");
            return;
        }

        println("Starting Anti-Debug Seeker Script for: " + currentProgram.getName());

        // --- Prompt for Configuration Files ---
        File configFile;
        File jsonFile;
        try {
            configFile = askFile("Select the Configuration File (.config)", "config");
            if (configFile == null) {
                println("Analysis cancelled: No config file selected.");
                return; // User cancelled
            }
            println("Using config file: " + configFile.getAbsolutePath());

            jsonFile = askFile("Select the JSON Description File (.json)", "json");
            if (jsonFile == null) {
                println("Analysis cancelled: No JSON description file selected.");
                return; // User cancelled
            }
            println("Using JSON file: " + jsonFile.getAbsolutePath());

        } catch (CancelledException e) {
             println("Analysis cancelled during file selection.");
             return;
        }

        // --- Load Configuration using selected paths ---
        println("Loading configuration from selected files...");
        AntiDebugConfig config;
        try {
            // Use the new method in AntiDebugConfig that accepts paths
            config = AntiDebugConfig.loadFromPaths(configFile.getAbsolutePath(), jsonFile.getAbsolutePath());
            println("Configuration loaded successfully.");
            // Log loaded rule counts (optional, now done within loadFromPaths)
            // println(String.format(" - API Rules: %d (%s)", config.getApiCalls().size(), config.isAnalyzeApiCallsEnabled() ? "Enabled" : "Disabled"));
            // ... etc ... log flags if needed ...
             println(String.format(" - CSV Output: %s %s", config.isCsvOutputEnabled() ? "Enabled" : "Disabled", config.isCsvOutputEnabled() && config.getCsvOutputPath() != null ? "("+config.getCsvOutputPath()+")" : ""));


             // Check if any analysis is actually enabled
            if (!config.isAnalyzeApiCallsEnabled() && !config.isAnalyzeKeywordsEnabled() &&
                !config.isAnalyzeInstructionsEnabled() && !config.isAnalyzeBytesEnabled()) {
                println("\nWarning: All analysis types are disabled in the configuration. No analysis performed.");
                Msg.showWarn(this, null, "Analysis Skipped", "All analysis types are disabled in the configuration.");
                return; // Stop if nothing to do
            }

        } catch (IOException e) {
            printerr("Error: Failed to load configuration files: " + e.getMessage());
            Msg.showError(this, null, "Configuration Error", "Failed to load configuration files:\n" + e.getMessage());
            e.printStackTrace(getPrintWriter(err)); // Print stack trace to console
            return; // Stop script
        } catch (Exception e) {
             printerr("Error: An unexpected error occurred while loading configuration: " + e.getMessage());
             Msg.showError(this, null, "Configuration Error", "An unexpected error occurred while loading configuration:\n" + e.getMessage());
             e.printStackTrace(getPrintWriter(err));
             return; // Stop script
        }

        // --- Run Analysis within a transaction ---
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
            printerr("\nError: An error occurred during analysis: " + e.getMessage());
            Msg.showError(this, null, "Analysis Error", "An error occurred during analysis:\n" + e.getMessage());
            e.printStackTrace(getPrintWriter(err)); // Print stack trace to console
            // Transaction will be rolled back (success remains false)
        } finally {
            // End the transaction, committing only if analysis completed successfully
            currentProgram.endTransaction(transactionID, success);
            println("Analysis transaction finished (Committed: " + success + ").");
        }
    }
}