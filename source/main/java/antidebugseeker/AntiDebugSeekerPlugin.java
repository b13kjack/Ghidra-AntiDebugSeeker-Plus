package antidebugseeker;

// --- Necessary Imports ---
import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData; // Use MenuData for menu paths
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException; // For config loading
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager; // Assuming this exists for icons

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
// --- End Imports ---

/**
 * Ghidra plugin to detect common anti-debugging techniques in a program.
 * It scans for specific API calls, keyword patterns, instructions, and byte sequences
 * based on configurable rules.
 * Corrected version includes basic error handling for icon loading.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE, // Or ALPHA/BETA depending on maturity
    packageName = "AntiDebugSeeker", // Match module name if applicable
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Anti-Debugging Technique Seeker",
    description = "Scans the program for common anti-debugging techniques (APIs, patterns, instructions, bytes) based on configuration files.",
    servicesRequired = { ProgramManager.class }, // Explicitly require ProgramManager if needed for currentProgram access (usually implicit via ProgramPlugin)
    servicesProvided = { }
)
//@formatter:on
public class AntiDebugSeekerPlugin extends ProgramPlugin {

    private static final String MENU_GROUP = "AntiDebugGroup"; // For grouping menu actions

    private AntiDebugComponentProvider provider;
    private DockingAction runAction;
    private DockingAction configureAction;

    /**
     * Plugin constructor.
     * @param tool The plugin tool that this plugin is added to.
     */
    public AntiDebugSeekerPlugin(PluginTool tool) {
        // Takes program (true), saves program (true -> because it adds bookmarks/comments)
        super(tool, true, true);
    }

    /**
     * Initializes the plugin, creating the component provider and actions.
     */
    @Override
    protected void init() {
        super.init();
        provider = new AntiDebugComponentProvider(tool, getName());
        createActions();
        // Add provider to the tool, but don't make it visible initially.
        // It will be shown when analysis runs or if the user opens it manually.
        tool.addComponentProvider(provider, false); // false = not initially visible
    }

    /**
     * Creates the docking actions for running analysis and configuration.
     */
    private void createActions() {
        // ** FIX: Add basic check/handling for icon loading **
        Icon runIcon = null;
        Icon configIcon = null;
        try {
            runIcon = ResourceManager.loadImage("images/toolbar.png"); // Example icon path
            configIcon = ResourceManager.loadImage("images/configure.png"); // Example icon path
            if (runIcon == null) {
                 Msg.warn(this, "Could not load run icon: images/toolbar.png");
            }
             if (configIcon == null) {
                 Msg.warn(this, "Could not load configure icon: images/configure.png");
            }
        } catch (Exception e) {
             Msg.error(this, "Error loading icons for AntiDebugSeekerPlugin", e);
             // Icons will remain null, actions will be created without them
        }


        // --- Run Analysis Action ---
        runAction = new DockingAction("Run Anti-Debug Scan", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                runAnalysis();
            }

            /** Action is enabled only when a program is open. */
            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return currentProgram != null;
            }
        };
        // Only set toolbar/menu data if icon loaded successfully
        if (runIcon != null) {
            runAction.setToolBarData(new ToolBarData(runIcon, MENU_GROUP)); // Add to toolbar
            runAction.setMenuBarData(new MenuData(
                new String[]{"Analysis", "Anti-Debug Seeker", "&Run Scan..."}, // Use '&' for mnemonic
                runIcon, // Add icon to menu too
                MENU_GROUP // Grouping key
            ));
        } else {
             // Fallback if icon failed to load
             runAction.setMenuBarData(new MenuData(
                new String[]{"Analysis", "Anti-Debug Seeker", "&Run Scan..."},
                null, // No icon
                MENU_GROUP
            ));
        }
        runAction.setDescription(getPluginDescription().getDescription()); // Use plugin description
        runAction.setHelpLocation(new HelpLocation(getName(), "Run_Analysis")); // Anchor in help file
        tool.addAction(runAction);

        // --- Configure Action ---
        configureAction = new DockingAction("Configure Anti-Debug Seeker", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showConfigDialog();
            }
            // No context check needed, configuration can be viewed anytime
        };
         if (configIcon != null) {
            configureAction.setToolBarData(new ToolBarData(configIcon, MENU_GROUP)); // Add to toolbar
            configureAction.setMenuBarData(new MenuData(
                new String[]{"Analysis", "Anti-Debug Seeker", "&View Configuration..."}, // Changed text slightly
                configIcon,
                MENU_GROUP
            ));
        } else {
             // Fallback if icon failed to load
             configureAction.setMenuBarData(new MenuData(
                new String[]{"Analysis", "Anti-Debug Seeker", "&View Configuration..."},
                null, // No icon
                MENU_GROUP
            ));
        }
        configureAction.setDescription("View the currently loaded rules and settings for the Anti-Debug Seeker."); // Updated description
        configureAction.setHelpLocation(new HelpLocation(getName(), "Configure_Action"));
        tool.addAction(configureAction);
    }

    /**
     * Displays the configuration dialog (currently view-only).
     */
    private void showConfigDialog() {
        AntiDebugConfigDialog dialog = new AntiDebugConfigDialog(tool); // Pass tool if needed by dialog
        tool.showDialog(dialog); // Use tool's dialog management
        // No action needed after closing view-only dialog
    }

    /**
     * Initiates the anti-debug analysis process.
     * Loads configuration and launches the analysis in a background thread using TaskLauncher.
     */
    private void runAnalysis() {
        if (currentProgram == null) {
            Msg.showError(this, provider.getComponent(), "Analysis Error", "No program is open.");
            return;
        }

        // Ensure the results window (provider) is visible and clear it
        if (!provider.isVisible()) {
             tool.showComponentProvider(provider, true); // Show and focus
        }
        provider.clear(); // Clear previous results
        provider.append("Starting Anti-Debug Analysis for: " + currentProgram.getName() + "\n");
        provider.append("Loading configuration...\n");

        AntiDebugConfig config;
        try {
            // Load the configuration using the default paths
            config = AntiDebugConfig.loadConfig();
            provider.append("Configuration loaded successfully.\n");

            // Log loaded rule counts and settings status
            provider.append(String.format(" - API Rules: %d (%s)\n", config.getApiCalls().size(), config.isAnalyzeApiCallsEnabled() ? "Enabled" : "Disabled"));
            provider.append(String.format(" - Keyword Group Rules: %d (%s)\n", config.getKeywordGroups().size(), config.isAnalyzeKeywordsEnabled() ? "Enabled" : "Disabled"));
            provider.append(String.format(" - Instruction Rules: %d (%s)\n", config.getInstructionRules().size(), config.isAnalyzeInstructionsEnabled() ? "Enabled" : "Disabled"));
            provider.append(String.format(" - Byte Sequence Rules: %d (%s)\n", config.getByteSequences().size(), config.isAnalyzeBytesEnabled() ? "Enabled" : "Disabled"));
            provider.append(String.format(" - CSV Output: %s %s\n", config.isCsvOutputEnabled() ? "Enabled" : "Disabled", config.isCsvOutputEnabled() && config.getCsvOutputPath() != null ? "("+config.getCsvOutputPath()+")" : ""));

            // Check if any analysis is actually enabled
            if (!config.isAnalyzeApiCallsEnabled() && !config.isAnalyzeKeywordsEnabled() &&
                !config.isAnalyzeInstructionsEnabled() && !config.isAnalyzeBytesEnabled()) {
                provider.append("\nWarning: All analysis types are disabled in the configuration. No analysis performed.\n");
                Msg.showWarn(this, provider.getComponent(), "Analysis Skipped", "All analysis types are disabled in the configuration.");
                return; // Stop if nothing to do
            }

        } catch (IOException | NotFoundException e) {
            // Handle errors loading config files (e.g., file not found)
            Msg.showError(this, provider.getComponent(), "Configuration Error", "Failed to load configuration files: " + e.getMessage());
            provider.append("\nError loading configuration: " + e.getMessage() + "\nCheck that rule files exist in the extension's 'data' directory.\n");
            Msg.error(this, "Configuration loading failed", e); // Log full stack trace
            return; // Stop analysis
        } catch (Exception e) {
             // Catch unexpected errors during config loading/parsing
            Msg.showError(this, provider.getComponent(), "Configuration Error", "An unexpected error occurred while loading configuration: " + e.getMessage());
            provider.append("\nUnexpected error loading configuration: " + e.getMessage() + "\n");
            Msg.error(this, "Unexpected configuration loading error", e);
            return; // Stop analysis
        }


        // Use TaskLauncher for background execution within a plugin
        // Manage the transaction carefully around the background task
        int transactionID = currentProgram.startTransaction("Anti-Debug Analysis");
        boolean transactionSuccess = false; // Track if transaction should be committed

        try {
            // Launch the analysis task modally (blocks user interaction with Ghidra until done/cancelled)
            TaskLauncher.launchModal("Anti-Debug Analysis", (monitor) -> {
                try {
                    // Pass the logger method reference (provider::append) and the monitor
                    AntiDebugAnalysisCore.analyzeProgram(currentProgram, config, provider::append, monitor);
                    // If analyzeProgram completes without exception, the task was successful (from analysis perspective)
                } catch (CancelledException e) {
                    // Don't log here, CancelledException is handled specifically after launchModal returns
                    throw e; // Re-throw CancelledException to signal cancellation
                } catch (Exception e) {
                    // Log errors that occur *during* the analysis core execution
                    provider.append("\nError during analysis core execution: " + e.getMessage() + "\n");
                    Msg.error(this, "Analysis core failed", e); // Log full stack trace
                    // Wrap in a RuntimeException to signal failure to the outer catch block
                    throw new RuntimeException("Analysis core failed", e);
                }
            });

            // If launchModal completes without throwing CancelledException or RuntimeException, analysis succeeded
            transactionSuccess = true;
            provider.append("\nAnalysis task completed successfully.\n"); // Log successful completion

        } catch (CancelledException e) {
            // User cancelled the task via the monitor dialog
            provider.append("\nAnalysis cancelled by user.\n");
            // transactionSuccess remains false, transaction will be aborted
        } catch (Exception e) {
            // Handle exceptions from launchModal itself or RuntimeExceptions re-thrown from the task
            Msg.showError(this, provider.getComponent(), "Analysis Error", "An error occurred launching or running the analysis task: " + e.getMessage());
            provider.append("\nError during analysis execution: " + e.getMessage() + "\n");
            // transactionSuccess remains false, transaction will be aborted
        } finally {
            // End the transaction *after* the background task finishes or is cancelled.
            // Commit changes only if transactionSuccess is true.
            currentProgram.endTransaction(transactionID, transactionSuccess);
            provider.append("Analysis transaction finished (Committed: " + transactionSuccess + ").\n");
        }
    }

    /**
     * Cleans up resources when the plugin is disposed.
     * Removes actions and the component provider.
     */
    @Override
    protected void dispose() {
        // Remove actions first to prevent them being called after disposal
        if (runAction != null) {
            tool.removeAction(runAction);
            runAction = null;
        }
        if (configureAction != null) {
            tool.removeAction(configureAction);
            configureAction = null;
        }

        // Remove and dispose the component provider
        if (provider != null) {
            tool.removeComponentProvider(provider);
            provider.dispose(); // Allow provider to clean up its resources (e.g., listeners)
            provider = null;
        }
        super.dispose(); // Call parent dispose
    }

    // =====================================================================================
    // Component Provider (Results Window) - Inner Class
    // =====================================================================================

    /**
     * Provides the GUI component (a scrollable text area) to display analysis logs and results.
     */
    private static class AntiDebugComponentProvider extends ComponentProvider {
        private JPanel mainPanel;
        private JTextArea logTextArea;
        private JScrollPane scrollPane;

        /**
         * Constructor.
         * @param tool The plugin tool.
         * @param owner The plugin name (used for identification).
         */
        protected AntiDebugComponentProvider(PluginTool tool, String owner) {
            super(tool, owner, owner); // Use owner for name and initial title
            buildPanel();
            setTitle("Anti-Debug Seeker Log"); // Set a specific title for the window
            setDefaultWindowPosition(WindowPosition.BOTTOM); // Place at bottom by default
            setHelpLocation(new HelpLocation(owner, "Results_Window")); // Optional help anchor
            // Make this component provider visible by default in the Window menu
            setVisible(true);
        }

        /** Builds the GUI panel containing a scrollable text area. */
        private void buildPanel() {
            mainPanel = new JPanel(new BorderLayout());
            logTextArea = new JTextArea();
            logTextArea.setEditable(false); // User cannot type in the log
            logTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); // Use monospaced font for better alignment
            logTextArea.setMargin(new Insets(5, 5, 5, 5)); // Add some padding inside the text area
            logTextArea.setLineWrap(true); // Wrap lines that are too long
            logTextArea.setWrapStyleWord(true); // Wrap at word boundaries
            scrollPane = new JScrollPane(logTextArea);
            mainPanel.add(scrollPane, BorderLayout.CENTER);
        }

        /** Returns the main GUI component for this provider. */
        @Override
        public JComponent getComponent() {
            return mainPanel;
        }

        /** Appends text to the log area. Ensures update happens on the Swing thread. */
        public void append(String text) {
            // Use invokeLater to ensure thread safety when updating GUI components
            SwingUtilities.invokeLater(() -> {
                logTextArea.append(text);
                // Automatically scroll to the bottom to show the latest messages
                logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
            });
        }

        /** Clears the log area. Ensures update happens on the Swing thread. */
        public void clear() {
            SwingUtilities.invokeLater(() -> logTextArea.setText(""));
        }

        /** Called when the component provider is closed by the user or Ghidra. */
        @Override
        public void closeComponent() {
            super.closeComponent();
            // The provider is removed from view, but not disposed unless the plugin is unloaded.
            // If you need cleanup when the window is closed, do it here.
        }

        /** Called when the plugin (owner) is disposed. */
        @Override
        public void dispose() {
            // Clean up any resources held by the provider itself (e.g., listeners)
            // In this case, there are likely no specific resources to clean up here.
            super.dispose();
        }
    }
}
