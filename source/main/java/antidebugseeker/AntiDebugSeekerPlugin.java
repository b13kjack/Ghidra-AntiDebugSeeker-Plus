package antidebugseeker;

// --- Necessary Imports (Ignoring resolution errors) ---
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
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE, // Or ALPHA/BETA depending on maturity
    packageName = "AntiDebugSeeker", // Match module name if applicable
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Anti-Debugging Technique Seeker",
    description = "Scans the program for common anti-debugging techniques (APIs, patterns, etc.) based on configuration files.",
    servicesRequired = { }, // Add services like ColorizingService if needed directly here
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
        // Takes program, saves program, has options (can be configured)
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
        // It will be shown when analysis runs.
        tool.addComponentProvider(provider, false);
    }

    /**
     * Creates the docking actions for running analysis and configuration.
     */
    private void createActions() {
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
        // Optional: Add an icon from your resources
        // Icon runIcon = ResourceManager.loadImage("images/your_icon.png");
        // runAction.setToolBarData(new ToolBarData(runIcon, MENU_GROUP));
        runAction.setMenuBarData(new MenuData(
            new String[]{"Analysis", "Anti-Debug Seeker", "&Run Scan..."}, // Use '&' for mnemonic
            null, // Icon can be null
            MENU_GROUP // Grouping key
        ));
        runAction.setDescription(getPluginDescription().getDescription()); // Use plugin description
        runAction.setHelpLocation(new HelpLocation(getName(), "Run_Analysis")); // Anchor in help file
        tool.addAction(runAction);

        // --- Configure Action ---
        configureAction = new DockingAction("Configure Anti-Debug Seeker", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showConfigDialog();
            }
            // No context check needed, configuration can be opened anytime
        };
        // Optional: Add a configuration icon
        // Icon configureIcon = ResourceManager.loadImage("images/configure.png");
        // configureAction.setToolBarData(new ToolBarData(configureIcon, MENU_GROUP)); // Add to toolbar if desired
        configureAction.setMenuBarData(new MenuData(
            new String[]{"Analysis", "Anti-Debug Seeker", "&Configure..."},
            null,
            MENU_GROUP
        ));
        configureAction.setDescription("Configure the rules and settings for the Anti-Debug Seeker.");
        configureAction.setHelpLocation(new HelpLocation(getName(), "Configure_Action"));
        tool.addAction(configureAction);
    }

    /**
     * Displays the configuration dialog.
     * TODO: Implement or refactor AntiDebugConfigDialog
     */
    private void showConfigDialog() {
        // Assuming AntiDebugConfigDialog is a JDialog or similar
        AntiDebugConfigDialog dialog = new AntiDebugConfigDialog(tool); // Pass tool if needed by dialog
        tool.showDialog(dialog); // Use tool's dialog management
        // After the dialog closes, we might need to reload config or update UI
        // depending on how the dialog works (e.g., if it saves changes directly).
    }

    /**
     * Initiates the anti-debug analysis process.
     * Loads configuration and launches the analysis in a background thread.
     */
    private void runAnalysis() {
        if (currentProgram == null) {
            Msg.showError(this, provider.getComponent(), "Analysis Error", "No program is open.");
            return;
        }

        // Ensure the results window (provider) is visible
        if (!provider.isVisible()) {
             provider.setVisible(true);
        }
        provider.clear(); // Clear previous results
        provider.append("Starting Anti-Debug Analysis for: " + currentProgram.getName() + "\n");
        provider.append("Loading configuration...\n");

        AntiDebugConfig config;
        try {
            // Load the refactored config
            config = AntiDebugConfig.loadConfig();
            provider.append("Configuration loaded successfully.\n");
            // Log loaded rule counts (optional)
            provider.append(String.format(" - API Rules: %d (%s)\n", config.getApiCalls().size(), config.isAnalyzeApiCallsEnabled() ? "Enabled" : "Disabled"));
            provider.append(String.format(" - Keyword Group Rules: %d (%s)\n", config.getKeywordGroups().size(), config.isAnalyzeKeywordsEnabled() ? "Enabled" : "Disabled"));
            provider.append(String.format(" - Instruction Rules: %d (%s)\n", config.getInstructions().size(), config.isAnalyzeInstructionsEnabled() ? "Enabled" : "Disabled"));
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
            // Handle errors loading config files
            Msg.showError(this, provider.getComponent(), "Configuration Error", "Failed to load configuration files: " + e.getMessage());
            provider.append("\nError loading configuration: " + e.getMessage() + "\n");
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
            TaskLauncher.launchModal("Anti-Debug Analysis", (monitor) -> {
                boolean analysisSuccess = false;
                try {
                    // Pass the logger method reference (provider::append)
                    AntiDebugAnalysisCore.analyzeProgram(currentProgram, config, provider::append, monitor);
                    analysisSuccess = true; // Mark as successful if no exceptions thrown
                } catch (CancelledException e) {
                    // Handled specifically after launchModal returns
                    throw e; // Re-throw CancelledException
                } catch (Exception e) {
                    // Log errors that occur *during* analysis
                    provider.append("\nError during analysis: " + e.getMessage() + "\n");
                    Msg.error(this, "Analysis failed", e); // Log full stack trace
                    // Don't show dialog here, let the outer catch handle it
                    throw new RuntimeException("Analysis core failed", e); // Wrap other exceptions
                } finally {
                    // End transaction *inside* the task thread *only if* it wasn't cancelled.
                    // If cancelled, the outer catch handles it.
                    // If other exception, the outer catch handles it.
                    // This 'finally' might not be the best place if exceptions occur *before* analysis starts.
                    // Let's move transaction end to *after* launchModal returns based on outcome.
                }
            });

            // If launchModal completes without throwing CancelledException or RuntimeException
            transactionSuccess = true;
            provider.append("\nAnalysis task completed.\n"); // Log completion

        } catch (CancelledException e) {
            // User cancelled the task via the monitor dialog
            provider.append("\nAnalysis cancelled by user.\n");
            // Transaction should be aborted (false)
        } catch (Exception e) {
            // Handle exceptions from launchModal itself or RuntimeExceptions from the task
            Msg.showError(this, provider.getComponent(), "Analysis Error", "An error occurred launching or running the analysis task: " + e.getMessage());
            provider.append("\nError during analysis execution: " + e.getMessage() + "\n");
            // Transaction should be aborted (false)
        } finally {
            // End the transaction based on whether the task completed successfully
            currentProgram.endTransaction(transactionID, transactionSuccess);
            provider.append("Analysis transaction finished (Committed: " + transactionSuccess + ").\n");
        }
    }

    /**
     * Cleans up resources when the plugin is disposed.
     */
    @Override
    protected void dispose() {
        // Remove actions first
        if (runAction != null) {
            tool.removeAction(runAction);
            runAction = null;
        }
        if (configureAction != null) {
            tool.removeAction(configureAction);
            configureAction = null;
        }

        // Remove and dispose the provider
        if (provider != null) {
            tool.removeComponentProvider(provider);
            provider.dispose(); // Allow provider to clean up its resources
            provider = null;
        }
        super.dispose();
    }

    // =====================================================================================
    // Component Provider (Results Window)
    // =====================================================================================

    /**
     * Provides the GUI component (a text area) to display analysis logs and results.
     */
    private static class AntiDebugComponentProvider extends ComponentProvider {
        private JPanel mainPanel;
        private JTextArea logTextArea;
        private JScrollPane scrollPane;

        /**
         * Constructor.
         * @param tool The plugin tool.
         * @param owner The plugin name.
         */
        protected AntiDebugComponentProvider(PluginTool tool, String owner) {
            super(tool, owner, owner); // Use owner for name and title initially
            buildPanel();
            setTitle("Anti-Debug Seeker Log"); // Set a specific title
            setDefaultWindowPosition(WindowPosition.BOTTOM); // Place at bottom by default
            // setHelpLocation(new HelpLocation(owner, "Results_Window")); // Optional help anchor
        }

        /** Builds the GUI panel with a scrollable text area. */
        private void buildPanel() {
            mainPanel = new JPanel(new BorderLayout());
            logTextArea = new JTextArea();
            logTextArea.setEditable(false);
            logTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); // Use monospaced font
            logTextArea.setMargin(new Insets(5, 5, 5, 5)); // Add some padding
            scrollPane = new JScrollPane(logTextArea);
            mainPanel.add(scrollPane, BorderLayout.CENTER);
        }

        /** Returns the main GUI component. */
        @Override
        public JComponent getComponent() {
            return mainPanel;
        }

        /** Appends text to the log area (thread-safe). */
        public void append(String text) {
            SwingUtilities.invokeLater(() -> {
                logTextArea.append(text);
                // Scroll to the bottom automatically
                logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
            });
        }

        /** Clears the log area (thread-safe). */
        public void clear() {
            SwingUtilities.invokeLater(() -> logTextArea.setText(""));
        }

        /** Called when the component provider is closed by the user or Ghidra. */
        @Override
        public void closeComponent() {
            super.closeComponent();
            // Optionally hide instead of removing if you want to preserve state
            // setVisible(false);
        }

        /** Called when the plugin is disposed. */
        @Override
        public void dispose() {
            // Clean up any resources held by the provider if necessary
            super.dispose();
        }
    }
}
