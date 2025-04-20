package antidebugseeker;

import docking.DialogComponentProvider; // Use Ghidra's dialog provider
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.IOException;
import java.util.stream.Collectors;

/**
 * A dialog to display the current configuration settings for the AntiDebugSeeker plugin.
 * Note: This version is display-only. Editing requires a more complex implementation.
 */
public class AntiDebugConfigDialog extends DialogComponentProvider {

    private AntiDebugConfig currentConfig;
    private JPanel mainPanel;

    /**
     * Constructor.
     * @param tool The plugin tool, used for context if needed.
     */
    public AntiDebugConfigDialog(PluginTool tool) {
        super("Anti-Debug Seeker Configuration", true, false, true, false); // Modal, not resizable
        loadConfiguration();
        addWorkPanel(buildMainPanel());
        addDismissButton(); // Add a standard "Dismiss" button
        setPreferredSize(500, 400); // Set a reasonable default size
    }

    /** Loads the configuration to be displayed. */
    private void loadConfiguration() {
        try {
            this.currentConfig = AntiDebugConfig.loadConfig();
        } catch (IOException | NotFoundException e) {
            Msg.showError(this, getComponent(), "Configuration Load Error",
                "Failed to load Anti-Debug Seeker configuration: " + e.getMessage());
            Msg.error(this, "Config load error", e);
            this.currentConfig = null; // Ensure config is null on error
        } catch (Exception e) {
             Msg.showError(this, getComponent(), "Configuration Load Error",
                "An unexpected error occurred loading configuration: " + e.getMessage());
            Msg.error(this, "Unexpected config load error", e);
            this.currentConfig = null;
        }
    }

    /** Builds the main panel displaying the configuration settings. */
    private JPanel buildMainPanel() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        if (currentConfig == null) {
            mainPanel.add(new JLabel("Error loading configuration. See logs for details."), BorderLayout.CENTER);
            return mainPanel;
        }

        // Use GridBagLayout for better alignment
        JPanel contentPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 5, 2, 5); // Padding

        // --- Analysis Toggles ---
        gbc.gridwidth = 2; // Span two columns for section header
        contentPanel.add(createHeaderLabel("Analysis Modules"), gbc);
        gbc.gridy++;
        gbc.gridwidth = 1; // Reset span

        contentPanel.add(new JLabel("API Call Analysis:"), gbc);
        gbc.gridx = 1;
        contentPanel.add(createReadOnlyCheckBox(currentConfig.isAnalyzeApiCallsEnabled()), gbc);
        gbc.gridy++;

        gbc.gridx = 0;
        contentPanel.add(new JLabel("Keyword Pattern Analysis:"), gbc);
        gbc.gridx = 1;
        contentPanel.add(createReadOnlyCheckBox(currentConfig.isAnalyzeKeywordsEnabled()), gbc);
        gbc.gridy++;

        gbc.gridx = 0;
        contentPanel.add(new JLabel("Instruction Analysis:"), gbc);
        gbc.gridx = 1;
        contentPanel.add(createReadOnlyCheckBox(currentConfig.isAnalyzeInstructionsEnabled()), gbc);
        gbc.gridy++;

        gbc.gridx = 0;
        contentPanel.add(new JLabel("Byte Sequence Analysis:"), gbc);
        gbc.gridx = 1;
        contentPanel.add(createReadOnlyCheckBox(currentConfig.isAnalyzeBytesEnabled()), gbc);
        gbc.gridy++;

        // --- General Settings ---
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(10, 5, 2, 5); // Add top margin
        contentPanel.add(createHeaderLabel("General Settings"), gbc);
        gbc.gridy++;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(2, 5, 2, 5); // Reset margin

        gbc.gridx = 0;
        contentPanel.add(new JLabel("Default Search Range:"), gbc);
        gbc.gridx = 1;
        contentPanel.add(new JLabel(String.valueOf(currentConfig.getDefaultSearchRange())), gbc);
        gbc.gridy++;

        // --- CSV Output Settings ---
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(10, 5, 2, 5);
        contentPanel.add(createHeaderLabel("CSV Output"), gbc);
        gbc.gridy++;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(2, 5, 2, 5);

        gbc.gridx = 0;
        contentPanel.add(new JLabel("Enable CSV Output:"), gbc);
        gbc.gridx = 1;
        contentPanel.add(createReadOnlyCheckBox(currentConfig.isCsvOutputEnabled()), gbc);
        gbc.gridy++;

        gbc.gridx = 0;
        contentPanel.add(new JLabel("CSV Output Path:"), gbc);
        gbc.gridx = 1;
        String csvPathStr = (currentConfig.getCsvOutputPath() != null)
                            ? currentConfig.getCsvOutputPath().toString()
                            : "(Not Set)";
        // Use JTextField to allow copying, but make it non-editable
        JTextField pathField = new JTextField(csvPathStr);
        pathField.setEditable(false);
        pathField.setBorder(null); // Remove border to look like a label
        pathField.setBackground(contentPanel.getBackground()); // Match background
        gbc.fill = GridBagConstraints.HORIZONTAL; // Allow path to expand
        contentPanel.add(pathField, gbc);
        gbc.fill = GridBagConstraints.NONE; // Reset fill
        gbc.gridy++;


        // --- Add Spacer to push content up ---
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.weighty = 1.0; // Give vertical space to this component
        gbc.fill = GridBagConstraints.VERTICAL;
        contentPanel.add(new JPanel(), gbc); // Empty panel as spacer

        // Add the content panel to the main panel
        mainPanel.add(contentPanel, BorderLayout.CENTER);

        // Optional: Add a note about display-only
        JLabel infoLabel = new JLabel("This dialog displays the current settings loaded from configuration files. Editing is not available here.");
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.ITALIC));
        mainPanel.add(infoLabel, BorderLayout.SOUTH);


        return mainPanel;
    }

    /** Helper to create a non-editable checkbox representing a boolean setting. */
    private JCheckBox createReadOnlyCheckBox(boolean isSelected) {
        JCheckBox checkBox = new JCheckBox();
        checkBox.setSelected(isSelected);
        checkBox.setEnabled(false); // Make it read-only
        return checkBox;
    }

     /** Helper to create a formatted header label. */
    private JLabel createHeaderLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        // Optional: Add a separator below
        // label.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY));
        return label;
    }

    /** Overridden to handle the dismiss action. */
    @Override
    protected void dismissCallback() {
        close(); // Close the dialog
    }
}
