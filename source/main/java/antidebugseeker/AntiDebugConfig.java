package antidebugseeker;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

/**
 * Manages the configuration for the AntiDebugSeeker plugin, loading rules
 * from .config files and descriptions from .json files.
 * Corrected version includes comment regarding relative paths.
 */
public class AntiDebugConfig {

    // --- Constants for Configuration Sections/Keys ---
    private static final String SECTION_API = "###Anti_Debug_API###"; // Match exact case/spacing in file
    private static final String SECTION_TECHNIQUE = "###Anti_Debug_Technique###"; // Match exact case/spacing in file
    private static final String SECTION_INSTRUCTION = "###Instructions###"; // Example, ensure matches config file if used
    private static final String SECTION_BYTES = "###Byte_Sequences###";   // Example, ensure matches config file if used
    private static final String KEY_DEFAULT_SEARCH_RANGE = "default_search_range=";
    private static final String KEY_SEARCH_RANGE = "search_range=";
    private static final String KEY_ENABLE_API_ANALYSIS = "enable_api_analysis=";
    private static final String KEY_ENABLE_KEYWORD_ANALYSIS = "enable_keyword_analysis=";
    private static final String KEY_ENABLE_INSTRUCTION_ANALYSIS = "enable_instruction_analysis=";
    private static final String KEY_ENABLE_BYTE_ANALYSIS = "enable_byte_analysis=";
    private static final String KEY_ENABLE_CSV_OUTPUT = "enable_csv_output=";
    private static final String KEY_CSV_OUTPUT_PATH = "csv_output_path=";

    // --- Configuration Data ---
    private final Map<String, String> apiCategories = new HashMap<>();
    private final Map<String, String> ruleDescriptions = new HashMap<>(); // Combined descriptions map
    private final List<KeywordGroup> keywordGroups = new ArrayList<>();
    private final List<String> apiCalls = new ArrayList<>();
    private final List<InstructionRule> instructionRules = new ArrayList<>(); // New: Complex instruction rules
    private final List<String> byteSequences = new ArrayList<>(); // Basic byte sequence list
    private int defaultSearchRange = 80; // Default value

    // --- Feature Flags/Settings ---
    private boolean analyzeApiCallsEnabled = true; // Default on
    private boolean analyzeKeywordsEnabled = true; // Default on
    private boolean analyzeInstructionsEnabled = false; // Default off unless explicitly defined/enabled
    private boolean analyzeBytesEnabled = false;      // Default off unless explicitly defined/enabled
    private boolean csvOutputEnabled = false; // Default off
    private Path csvOutputPath = null; // Default to null, set from config

    /** Private constructor to force use of factory methods like {@link #loadConfig()} or {@link #loadFromPaths(String, String)}. */
    private AntiDebugConfig() {}

    // --- Getters ---
    public List<String> getApiCalls() { return Collections.unmodifiableList(apiCalls); }
    public List<InstructionRule> getInstructionRules() { return Collections.unmodifiableList(instructionRules); }
    public List<String> getByteSequences() { return Collections.unmodifiableList(byteSequences); }
    public List<KeywordGroup> getKeywordGroups() { return Collections.unmodifiableList(keywordGroups); }
    public String getApiCategory(String apiName) { return apiCategories.getOrDefault(apiName, "Unknown Category"); }
    public String getRuleDescription(String ruleName) { return ruleDescriptions.getOrDefault(ruleName, "No description available."); }
    public int getDefaultSearchRange() { return defaultSearchRange; }

    // Feature Getters
    public boolean isAnalyzeApiCallsEnabled() { return analyzeApiCallsEnabled; }
    public boolean isAnalyzeKeywordsEnabled() { return analyzeKeywordsEnabled; }
    public boolean isAnalyzeInstructionsEnabled() { return analyzeInstructionsEnabled; }
    public boolean isAnalyzeBytesEnabled() { return analyzeBytesEnabled; }
    public boolean isCsvOutputEnabled() { return csvOutputEnabled; }
    public Path getCsvOutputPath() { return csvOutputPath; }

    // --- Loading Logic ---

    /**
     * Loads the configuration from default file locations within the Ghidra module data directory.
     * Assumes config file: data/anti_debug_Ghidra.config
     * Assumes JSON file: data/anti_debug_techniques_descriptions_Ghidra.json
     *
     * @return A loaded AntiDebugConfig instance.
     * @throws IOException If file reading fails.
     * @throws NotFoundException If the module data directory or config files cannot be found.
     */
    public static AntiDebugConfig loadConfig() throws IOException, NotFoundException {
        AntiDebugConfig config = new AntiDebugConfig();
        String configModuleName = "AntiDebugSeeker"; // Should match your extension's name
        String configDataDir = "data"; // Standard subdirectory for data files

        // --- Find and Load JSON Descriptions ---
        String jsonFileName = "anti_debug_techniques_descriptions_Ghidra.json";
        File jsonFile = Application.getModuleDataFile(configModuleName, configDataDir + "/" + jsonFileName).getFile(false);
        if (!jsonFile.exists() || !jsonFile.isFile()) {
            throw new IOException("JSON description file not found or is not a file: " + jsonFile.getAbsolutePath());
        }
        config.parseJsonDescriptions(Files.readString(jsonFile.toPath()));
        Msg.info(AntiDebugConfig.class, "Loaded " + config.ruleDescriptions.size() + " descriptions from " + jsonFileName);

        // --- Find and Load Config Rules ---
        String configFileName = "anti_debug_Ghidra.config";
        File configFile = Application.getModuleDataFile(configModuleName, configDataDir + "/" + configFileName).getFile(false);
         if (!configFile.exists() || !configFile.isFile()) {
            throw new IOException("Config rule file not found or is not a file: " + configFile.getAbsolutePath());
        }
        config.parseConfigFile(configFile.getAbsolutePath()); // Use the parsing method
        Msg.info(AntiDebugConfig.class, "Loaded config from " + configFileName);
        logLoadedCounts(config); // Log counts after parsing

        return config;
    }

    /**
     * Loads the configuration from explicitly provided file paths.
     * Used by the standalone script.
     *
     * @param configPath Path to the .config file.
     * @param jsonPath Path to the .json file.
     * @return A loaded AntiDebugConfig instance.
     * @throws IOException If file reading fails or files don't exist.
     */
     public static AntiDebugConfig loadFromPaths(String configPath, String jsonPath) throws IOException {
        AntiDebugConfig config = new AntiDebugConfig();

        // --- Load JSON Descriptions ---
        File jsonFile = new File(jsonPath);
        if (!jsonFile.exists() || !jsonFile.isFile()) {
            throw new IOException("JSON description file not found or is not a file: " + jsonPath);
        }
        config.parseJsonDescriptions(Files.readString(jsonFile.toPath()));
        Msg.info(AntiDebugConfig.class, "Loaded " + config.ruleDescriptions.size() + " descriptions from " + jsonPath);


        // --- Load Config Rules ---
        File configFile = new File(configPath);
        if (!configFile.exists() || !configFile.isFile()) {
            throw new IOException("Config rule file not found or is not a file: " + configPath);
        }
        config.parseConfigFile(configPath); // Use the parsing method
        Msg.info(AntiDebugConfig.class, "Loaded config from " + configPath);
        logLoadedCounts(config); // Log counts after parsing

        return config;
     }

     /** Helper method to log the counts of loaded rules. */
     private static void logLoadedCounts(AntiDebugConfig config) {
        Msg.info(AntiDebugConfig.class, " - API Rules: " + config.apiCalls.size());
        Msg.info(AntiDebugConfig.class, " - Keyword Group Rules: " + config.keywordGroups.size());
        Msg.info(AntiDebugConfig.class, " - Instruction Rules: " + config.instructionRules.size());
        Msg.info(AntiDebugConfig.class, " - Byte Sequence Rules: " + config.byteSequences.size());
        Msg.info(AntiDebugConfig.class, " - Default Search Range: " + config.defaultSearchRange);
        Msg.info(AntiDebugConfig.class, " - API Analysis Enabled: " + config.analyzeApiCallsEnabled);
        Msg.info(AntiDebugConfig.class, " - Keyword Analysis Enabled: " + config.analyzeKeywordsEnabled);
        Msg.info(AntiDebugConfig.class, " - Instruction Analysis Enabled: " + config.analyzeInstructionsEnabled);
        Msg.info(AntiDebugConfig.class, " - Byte Analysis Enabled: " + config.analyzeBytesEnabled);
        Msg.info(AntiDebugConfig.class, " - CSV Output Enabled: " + config.csvOutputEnabled);
        if (config.csvOutputEnabled && config.csvOutputPath != null) {
             Msg.info(AntiDebugConfig.class, " - CSV Output Path: " + config.csvOutputPath);
        }
     }


    /** Parses the JSON string containing rule descriptions. */
    private void parseJsonDescriptions(String jsonString) {
        Gson gson = new Gson();
        int warnings = 0;
        try {
            Type type = new TypeToken<Map<String, String>>(){}.getType();
            Map<String, String> loadedDescriptions = gson.fromJson(jsonString, type);

            if (loadedDescriptions == null) {
                 Msg.error(this, "Failed to parse JSON descriptions: Resulting map is null.");
                 return; // Cannot proceed
            }

            for (Map.Entry<String, String> entry : loadedDescriptions.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                if (key == null || key.trim().isEmpty()) {
                    Msg.warn(this, "JSON Description Warning: Found entry with null or empty key. Skipping.");
                    warnings++;
                    continue;
                }
                if (value == null) {
                     Msg.warn(this, "JSON Description Warning: Found null value for key '" + key + "'. Using empty description.");
                     warnings++;
                     value = ""; // Use empty string instead of null
                }

                // Clean up potential escape sequences and trailing periods
                String cleanedValue = value.replace("\\n", "\n").replace("\\\"", "\"").trim();
                // Removed trailing period removal, as it might be intentional
                // if (cleanedValue.endsWith(".")) {
                //     cleanedValue = cleanedValue.substring(0, cleanedValue.length() - 1);
                // }
                this.ruleDescriptions.put(key.trim(), cleanedValue);
            }

            if (warnings > 0) {
                Msg.warn(this, "JSON parsing completed with " + warnings + " warnings.");
            }

        } catch (JsonSyntaxException e) {
            Msg.error(this, "Failed to parse JSON descriptions: " + e.getMessage(), e);
            // Continue without descriptions, but log the error.
        }
    }

    /** Parses the .config file containing analysis rules and settings. */
    private void parseConfigFile(String filePath) throws IOException {
        String line;
        int lineNumber = 0;
        int warningCount = 0;
        String currentSection = "";
        String currentRuleName = "";
        List<String> currentKeywords = new ArrayList<>();
        int currentSearchRange = -1; // Use -1 to indicate rule-specific range not set yet
        String currentCategory = ""; // For API section

        // For Instruction Parsing state
        InstructionRule currentInstructionRule = null;
        InstructionStep currentInstructionStep = null;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                // Strip comments (// or #) first, then trim whitespace
                String originalLine = line; // Keep for potential error messages if needed
                line = line.split("//", 2)[0].split("#", 2)[0].trim();

                if (line.isEmpty()) { // Skip empty lines and lines that were only comments
                    continue;
                }

                // --- Global Settings (Check before section logic) ---
                // Use startsWithIgnoreCase for robustness
                if (line.toLowerCase().startsWith(KEY_DEFAULT_SEARCH_RANGE)) {
                    warningCount += parseIntegerSetting(line, KEY_DEFAULT_SEARCH_RANGE, lineNumber, val -> this.defaultSearchRange = val);
                    continue; // Processed, move to next line
                }
                if (line.toLowerCase().startsWith(KEY_ENABLE_API_ANALYSIS)) {
                    warningCount += parseBooleanSetting(line, KEY_ENABLE_API_ANALYSIS, lineNumber, val -> this.analyzeApiCallsEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_KEYWORD_ANALYSIS)) {
                    warningCount += parseBooleanSetting(line, KEY_ENABLE_KEYWORD_ANALYSIS, lineNumber, val -> this.analyzeKeywordsEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_INSTRUCTION_ANALYSIS)) {
                    warningCount += parseBooleanSetting(line, KEY_ENABLE_INSTRUCTION_ANALYSIS, lineNumber, val -> this.analyzeInstructionsEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_BYTE_ANALYSIS)) {
                    warningCount += parseBooleanSetting(line, KEY_ENABLE_BYTE_ANALYSIS, lineNumber, val -> this.analyzeBytesEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_CSV_OUTPUT)) {
                    warningCount += parseBooleanSetting(line, KEY_ENABLE_CSV_OUTPUT, lineNumber, val -> this.csvOutputEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_CSV_OUTPUT_PATH)) {
                    warningCount += parsePathSetting(line, KEY_CSV_OUTPUT_PATH, lineNumber, val -> this.csvOutputPath = val);
                    continue;
                }

                // --- Section Handling ---
                // Use the exact section headers from constants
                if (line.equals(SECTION_API) || line.equals(SECTION_TECHNIQUE) || line.equals(SECTION_INSTRUCTION) || line.equals(SECTION_BYTES)) {
                    // Finalize previous group/rule before switching sections
                    finalizeKeywordGroup(currentSection, currentRuleName, currentKeywords, currentSearchRange);
                    finalizeInstructionRule(currentSection, currentInstructionRule, currentInstructionStep); // Pass current step

                    currentSection = line; // Store the exact section header found
                    // Reset state for the new section
                    currentRuleName = "";
                    currentKeywords.clear();
                    currentCategory = "";
                    currentSearchRange = -1;
                    currentInstructionRule = null;
                    currentInstructionStep = null;

                    Msg.debug(this, "Entering section: " + currentSection);
                    continue; // Move to next line after processing section header
                }

                // --- Section-Specific Parsing ---
                switch (currentSection) {
                    case SECTION_API:
                        if (line.startsWith("[") && line.endsWith("]")) {
                            // New API category
                            currentCategory = line.substring(1, line.length() - 1).trim();
                            if (currentCategory.isEmpty()) {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty API category '[]' found. Using 'Default'.", lineNumber));
                                currentCategory = "Default";
                            }
                        } else {
                            // API name under the current category
                            String apiName = line;
                            if (!apiName.isEmpty()) {
                                apiCalls.add(apiName);
                                apiCategories.put(apiName, currentCategory.isEmpty() ? "Default" : currentCategory);
                            } else {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty API name found in category '%s'. Skipping.", lineNumber, currentCategory));
                                warningCount++;
                            }
                        }
                        break;

                    case SECTION_TECHNIQUE:
                        if (line.startsWith("[") && line.endsWith("]")) {
                            // Finalize previous keyword group before starting new one
                            finalizeKeywordGroup(currentSection, currentRuleName, currentKeywords, currentSearchRange);

                            // Start new keyword group
                            currentRuleName = line.substring(1, line.length() - 1).trim();
                            if (currentRuleName.isEmpty()) {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty Technique rule name '[]' found. Rule will be skipped.", lineNumber));
                                warningCount++;
                                currentRuleName = ""; // Ensure it's marked as invalid/empty
                            }
                            currentSearchRange = -1; // Reset rule-specific range for the new rule
                            currentKeywords.clear(); // Clear keywords for the new rule
                        } else if (line.toLowerCase().startsWith(KEY_SEARCH_RANGE)) {
                            // Rule-specific search range override (only applies if inside a rule)
                             if (!currentRuleName.isEmpty()) {
                                 warningCount += parseIntegerSetting(line, KEY_SEARCH_RANGE, lineNumber, val -> currentSearchRange = val);
                             } else {
                                 Msg.warn(this, String.format("Config Parse Warning (Line %d): '%s' found outside a rule definition [RuleName] in %s. Ignoring.", lineNumber, KEY_SEARCH_RANGE, SECTION_TECHNIQUE));
                                 warningCount++;
                             }
                        } else if (!currentRuleName.isEmpty()) {
                            // Keyword belonging to the current rule
                            String keyword = line;
                            if (!keyword.isEmpty()) {
                                currentKeywords.add(keyword);
                            } else {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty keyword found in rule '%s'. Skipping keyword.", lineNumber, currentRuleName));
                                warningCount++;
                            }
                        } else {
                             // Line appears before the first [RuleName] in this section
                             Msg.warn(this, String.format("Config Parse Warning (Line %d): Keyword line '%s' found outside a rule definition [RuleName] in %s. Ignoring.", lineNumber, line, SECTION_TECHNIQUE));
                             warningCount++;
                        }
                        break;

                    case SECTION_INSTRUCTION:
                        if (line.startsWith("[") && line.endsWith("]")) {
                            // Finalize previous instruction rule before starting a new one
                            finalizeInstructionRule(currentSection, currentInstructionRule, currentInstructionStep);

                            // Start new instruction rule
                            currentRuleName = line.substring(1, line.length() - 1).trim();
                             if (currentRuleName.isEmpty()) {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty Instruction rule name '[]' found. Rule will be skipped.", lineNumber));
                                warningCount++;
                                currentRuleName = ""; // Mark as invalid
                                currentInstructionRule = null;
                            } else {
                                currentInstructionRule = new InstructionRule(currentRuleName, new ArrayList<>());
                            }
                            currentInstructionStep = null; // Reset step for new rule
                        }
                        // Check for instruction step *only if* inside a valid rule
                        else if (currentInstructionRule != null && line.toLowerCase().startsWith("step:")) {
                             // Finalize previous step before starting a new one within the same rule
                             if (currentInstructionStep != null && !currentInstructionStep.getOperandChecks().isEmpty()) { // Only add if it has checks
                                 currentInstructionRule.addStep(currentInstructionStep);
                             } else if (currentInstructionStep != null) {
                                 Msg.warn(this, String.format("Config Parse Warning (Line %d): Instruction step '%s' in rule '%s' has no operand checks defined. Step might not be effective.", lineNumber, currentInstructionStep.getMnemonic(), currentRuleName));
                                 currentInstructionRule.addStep(currentInstructionStep); // Add anyway? Or skip? Adding for now.
                             }

                             String mnemonic = line.substring("Step:".length()).trim();
                             if (!mnemonic.isEmpty()) {
                                 currentInstructionStep = new InstructionStep(mnemonic, new ArrayList<>());
                             } else {
                                 Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty mnemonic in 'Step:' line for rule '%s'. Step skipped.", lineNumber, currentRuleName));
                                 warningCount++;
                                 currentInstructionStep = null; // Invalidate current step
                             }
                        }
                        // Check for operand *only if* inside a valid step
                        else if (currentInstructionStep != null && line.toLowerCase().startsWith("operand")) {
                            // Parse Operand check: Operand<index>: <check_type>:<value>
                            // Example: Operand0: REG:EAX, Operand1: VAL:0x10, Operand0: TYPE:scalar
                            String operandPart = line.substring("Operand".length()).trim(); // "0: REG:EAX"
                            int firstColonIndex = operandPart.indexOf(":");
                            if (firstColonIndex <= 0) { // Need index before first colon, index cannot be empty
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Malformed Operand line (missing or misplaced index/first colon): '%s' in rule '%s'", lineNumber, line, currentRuleName));
                                warningCount++;
                                continue; // Skip this malformed line
                            }
                            String indexPart = operandPart.substring(0, firstColonIndex).trim(); // "0"
                            String checkPart = operandPart.substring(firstColonIndex + 1).trim(); // "REG:EAX"

                            if (!indexPart.matches("\\d+")) {
                                 Msg.warn(this, String.format("Config Parse Warning (Line %d): Invalid Operand index format: '%s' in '%s' in rule '%s'", lineNumber, indexPart, line, currentRuleName));
                                 warningCount++;
                                 continue;
                            }
                            int operandIndex = Integer.parseInt(indexPart);

                            int secondColonIndex = checkPart.indexOf(":");
                            if (secondColonIndex <= 0 || secondColonIndex == checkPart.length() - 1) { // Need type and value, type cannot be empty
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Malformed Operand check (missing or misplaced type/value/second colon): '%s' in '%s' in rule '%s'", lineNumber, checkPart, line, currentRuleName));
                                warningCount++;
                                continue;
                            }
                            String checkTypeStr = checkPart.substring(0, secondColonIndex).trim().toUpperCase(); // "REG"
                            String checkValue = checkPart.substring(secondColonIndex + 1).trim(); // "EAX"

                            if (checkValue.isEmpty()) {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty check value for Operand check type '%s' in '%s' in rule '%s'", lineNumber, checkTypeStr, line, currentRuleName));
                                warningCount++;
                                continue;
                            }

                            try {
                                OperandCheck.CheckType checkType = OperandCheck.CheckType.valueOf(checkTypeStr);
                                currentInstructionStep.addOperandCheck(new OperandCheck(operandIndex, checkType, checkValue));
                            } catch (IllegalArgumentException e) {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Invalid Operand check type: '%s' in '%s' in rule '%s'. Valid types: %s", lineNumber, checkTypeStr, line, currentRuleName, Arrays.toString(OperandCheck.CheckType.values())));
                                warningCount++;
                            }

                        } else if (currentInstructionRule != null) {
                             // Line isn't a new rule, step, or operand, but we are inside a rule definition
                             Msg.warn(this, String.format("Config Parse Warning (Line %d): Unexpected line '%s' within instruction rule '%s' in %s. Ignoring.", lineNumber, line, currentRuleName, SECTION_INSTRUCTION));
                             warningCount++;
                        } else {
                             // Line appears before the first [RuleName] in this section
                             Msg.warn(this, String.format("Config Parse Warning (Line %d): Unexpected line '%s' in %s before first rule definition [RuleName]. Ignoring.", lineNumber, line, SECTION_INSTRUCTION));
                             warningCount++;
                        }
                        break;

                    case SECTION_BYTES:
                        // Add non-empty lines as byte sequences
                        if (!line.isEmpty()) {
                            // Basic validation: check if it looks like hex (allow spaces)
                            if (line.matches("^[\\s0-9a-fA-F]+$")) {
                                byteSequences.add(line.replaceAll("\\s", "")); // Store without spaces
                            } else {
                                Msg.warn(this, String.format("Config Parse Warning (Line %d): Invalid characters found in byte sequence '%s'. Skipping sequence. Only hex characters (0-9, A-F) and spaces are allowed.", lineNumber, line));
                                warningCount++;
                            }
                        } else {
                             Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty line found in %s. Skipping.", lineNumber, SECTION_BYTES));
                             warningCount++;
                        }
                        break;

                    default:
                        // Line outside known section or before first section
                        if (!currentSection.isEmpty()) { // Only warn if we thought we were in a section
                           Msg.warn(this, String.format("Config Parse Warning (Line %d): Unexpected line '%s' in section '%s'. Ignoring.", lineNumber, line, currentSection));
                           warningCount++;
                        } else {
                           // Could be a comment or setting before the first section header
                           Msg.debug(this, String.format("Config Parse Debug (Line %d): Line '%s' found before first section header.", lineNumber, line));
                        }
                        break;
                }
            }

            // Finalize the last group/rule if the file ends within that section
            finalizeKeywordGroup(currentSection, currentRuleName, currentKeywords, currentSearchRange);
            finalizeInstructionRule(currentSection, currentInstructionRule, currentInstructionStep); // Pass last step

            if (warningCount > 0) {
                 Msg.warn(this, "Config file parsing completed with " + warningCount + " warnings. Processed " + lineNumber + " lines.");
            } else {
                 Msg.info(this, "Config file parsing complete. Processed " + lineNumber + " lines.");
            }


        } // try-with-resources ensures reader is closed
    }

    /** Helper to finalize adding a KeywordGroup. */
    private void finalizeKeywordGroup(String currentSection, String ruleName, List<String> keywords, int searchRange) {
        // Check if we were actually in the Technique section and have a valid rule name and keywords
        if (SECTION_TECHNIQUE.equals(currentSection) && !ruleName.isEmpty() && !keywords.isEmpty()) {
            int rangeToUse = (searchRange >= 0) ? searchRange : this.defaultSearchRange; // Use rule-specific range if set, else default
            String description = ruleDescriptions.getOrDefault(ruleName, "No description provided."); // Get description from JSON map
            keywordGroups.add(new KeywordGroup(ruleName, new ArrayList<>(keywords), rangeToUse, description));
             Msg.debug(this,"Finalized keyword group: '" + ruleName + "' with " + keywords.size() + " keywords, range " + rangeToUse);
        } else if (SECTION_TECHNIQUE.equals(currentSection) && !ruleName.isEmpty() && keywords.isEmpty()) {
            // Warn if a rule was defined but had no keywords
             Msg.warn(this, "Config Parse Warning: Keyword rule '" + ruleName + "' has no keywords defined. Skipping rule.");
        }
        // State is reset when a new rule starts or section changes.
    }

    /** Helper to finalize adding an InstructionRule. Needs the last step parsed. */
    private void finalizeInstructionRule(String currentSection, InstructionRule rule, InstructionStep lastStep) {
        // Check if we were in the Instruction section and have a valid rule object
        if (SECTION_INSTRUCTION.equals(currentSection) && rule != null) {
            // Finalize the last step if it exists and has checks
            if (lastStep != null && !lastStep.getOperandChecks().isEmpty()) {
                rule.addStep(lastStep);
            } else if (lastStep != null) {
                 Msg.warn(this, "Config Parse Warning: Final instruction step '" + lastStep.getMnemonic() + "' in rule '" + rule.getName() + "' has no operand checks. Step might not be effective.");
                 rule.addStep(lastStep); // Add anyway
            }

            // Now, check if the rule has any steps added
            if (!rule.getSteps().isEmpty()) {
                 instructionRules.add(rule);
                 Msg.debug(this,"Finalized instruction rule: '" + rule.getName() + "' with " + rule.getSteps().size() + " steps.");
            } else {
                 Msg.warn(this, "Config Parse Warning: Instruction rule '" + rule.getName() + "' has no valid steps defined. Skipping rule.");
            }
        }
        // State is reset when a new rule starts or section changes.
    }


    /** Helper to parse boolean settings. Returns 1 if a warning was issued, 0 otherwise. */
    private int parseBooleanSetting(String line, String key, int lineNumber, java.util.function.Consumer<Boolean> setter) {
        String value = line.substring(key.length()).trim().toLowerCase();
        if (value.equals("true")) {
            setter.accept(true);
            return 0;
        } else if (value.equals("false")) {
            setter.accept(false); // Corrected: Set to false when "false" is found
            return 0;
        } else {
            Msg.warn(this, String.format("Config Parse Warning (Line %d): Invalid boolean value for %s: '%s'. Expected 'true' or 'false'. Using default/previous value.", lineNumber, key.replace("=",""), value));
            return 1; // Warning issued
        }
    }

    /** Helper to parse integer settings. Returns 1 if a warning was issued, 0 otherwise. */
    private int parseIntegerSetting(String line, String key, int lineNumber, java.util.function.IntConsumer setter) {
        String value = line.substring(key.length()).trim();
        try {
            int intValue = Integer.parseInt(value);
            // Optional: Add range checks if necessary (e.g., search range > 0)
            if (key.contains("range") && intValue <= 0) {
                 Msg.warn(this, String.format("Config Parse Warning (Line %d): Non-positive integer value for %s: '%s'. Using default/previous value.", lineNumber, key.replace("=",""), value));
                 return 1;
            }
            setter.accept(intValue);
            return 0;
        } catch (NumberFormatException e) {
             Msg.warn(this, String.format("Config Parse Warning (Line %d): Invalid integer value for %s: '%s'. Using default/previous value.", lineNumber, key.replace("=",""), value));
             return 1; // Warning issued
        }
    }

     /** Helper to parse path settings. Returns 1 if a warning was issued, 0 otherwise. */
    private int parsePathSetting(String line, String key, int lineNumber, java.util.function.Consumer<Path> setter) {
        String value = line.substring(key.length()).trim();
        if (value.isEmpty()) {
             Msg.warn(this, String.format("Config Parse Warning (Line %d): Empty path specified for %s. Setting ignored.", lineNumber, key.replace("=","")));
             return 1;
        }
        try {
            // ** FIX: Add comment about relative paths **
            // NOTE: Relative paths are resolved against the Ghidra process's current working directory (CWD).
            // This CWD may vary depending on how Ghidra is launched.
            // Using absolute paths is generally recommended for clarity and reliability unless the CWD behavior is specifically intended.
            Path path = Paths.get(value);
            // We don't validate existence or writability here, just path syntax. CsvResultWriter will handle creation/write errors.
            setter.accept(path);
            return 0;
        } catch (InvalidPathException e) {
             Msg.warn(this, String.format("Config Parse Warning (Line %d): Invalid path syntax for %s: '%s'. Setting ignored.", lineNumber, key.replace("=",""), value), e); // Log exception details
             return 1; // Warning issued
        }
    }


    // --- Inner Class for Keyword Groups ---
    /** Represents a group of keywords defining an anti-debug technique pattern. */
    public static class KeywordGroup {
        private final String name;
        private final List<String> keywords;
        private final int searchRange;
        private final String description;

        public KeywordGroup(String name, List<String> keywords, int searchRange, String description) {
            this.name = Objects.requireNonNull(name, "KeywordGroup name cannot be null").trim();
            this.keywords = Collections.unmodifiableList(new ArrayList<>(Objects.requireNonNull(keywords, "Keyword list cannot be null")));
            this.searchRange = searchRange;
            this.description = Objects.requireNonNull(description, "Description cannot be null"); // Allow empty description ""

            if (this.name.isEmpty()) {
                 throw new IllegalArgumentException("KeywordGroup name cannot be empty");
            }
            if (this.keywords.isEmpty()) {
                throw new IllegalArgumentException("KeywordGroup must contain at least one keyword: " + name);
            }
             if (this.searchRange <= 0) {
                 throw new IllegalArgumentException("KeywordGroup searchRange must be positive: " + name);
            }
        }

        // --- Getters ---
        public String getName() { return name; }
        public List<String> getKeywords() { return keywords; }
        public int getSearchRange() { return searchRange; }
        public String getDescription() { return description; }

        // --- Helper Methods ---
        public String getPrimaryKeyword() {
            return keywords.get(0); // Assumes list is not empty (checked in constructor)
        }

        public List<String> getSecondaryKeywords() {
            return keywords.size() > 1 ? keywords.subList(1, keywords.size()) : Collections.emptyList();
        }

        public String getKeywordByIndex(int index) {
            return (index >= 0 && index < keywords.size()) ? keywords.get(index) : null;
        }

        @Override
        public String toString() {
            return "KeywordGroup{" +
                   "name='" + name + '\'' +
                   ", keywords=" + keywords +
                   ", searchRange=" + searchRange +
                   '}';
        }
    }

    // --- Inner Classes for Instruction Rules ---
    /** Represents a complete instruction sequence rule. */
    public static class InstructionRule {
        private final String name;
        private final List<InstructionStep> steps;

        public InstructionRule(String name, List<InstructionStep> steps) {
            this.name = Objects.requireNonNull(name, "InstructionRule name cannot be null").trim();
            this.steps = new ArrayList<>(Objects.requireNonNull(steps, "Instruction steps list cannot be null"));
             if (this.name.isEmpty()) {
                 throw new IllegalArgumentException("InstructionRule name cannot be empty");
            }
        }

        public String getName() { return name; }
        public List<InstructionStep> getSteps() { return Collections.unmodifiableList(steps); }

        // Helper to add steps during parsing
        // Make sure this is only called internally during parsing
        void addStep(InstructionStep step) {
            this.steps.add(Objects.requireNonNull(step));
        }

        @Override
        public String toString() {
            return "InstructionRule{" +
                   "name='" + name + '\'' +
                   ", steps=" + steps.size() + " steps" +
                   '}';
        }
    }

    /** Represents a single instruction within an instruction sequence rule. */
    public static class InstructionStep {
        private final String mnemonic;
        private final List<OperandCheck> operandChecks;

        public InstructionStep(String mnemonic, List<OperandCheck> operandChecks) {
            this.mnemonic = Objects.requireNonNull(mnemonic, "InstructionStep mnemonic cannot be null").trim();
            this.operandChecks = new ArrayList<>(Objects.requireNonNull(operandChecks, "Operand checks list cannot be null"));
             if (this.mnemonic.isEmpty()) {
                 throw new IllegalArgumentException("InstructionStep mnemonic cannot be empty");
            }
        }

        public String getMnemonic() { return mnemonic; }
        public List<OperandCheck> getOperandChecks() { return Collections.unmodifiableList(operandChecks); }

         // Helper to add checks during parsing
         // Make sure this is only called internally during parsing
        void addOperandCheck(OperandCheck check) {
            this.operandChecks.add(Objects.requireNonNull(check));
        }

        @Override
        public String toString() {
            return "InstructionStep{" +
                   "mnemonic='" + mnemonic + '\'' +
                   ", operandChecks=" + operandChecks.size() + " checks" +
                   '}';
        }
    }

    /** Represents a check to perform on a specific operand. */
    public static class OperandCheck {
        // REG: Check if operand is a register matching the name (e.g., "EAX", "rax") - Case-insensitive.
        // VAL: Check if operand is a scalar/constant value matching the string (e.g., "0x10", "123", "-1") - Handles hex/decimal, compares signed/unsigned.
        // TYPE: Check the Ghidra OperandType string (e.g., "Register", "Scalar", "Address", "CodeAddress") - Case-insensitive.
        public enum CheckType { REG, VAL, TYPE }

        private final int operandIndex;
        private final CheckType checkType;
        private final String value; // Register name, value string (hex/dec), or type string

        public OperandCheck(int operandIndex, CheckType checkType, String value) {
            if (operandIndex < 0) throw new IllegalArgumentException("Operand index cannot be negative");
            this.operandIndex = operandIndex;
            this.checkType = Objects.requireNonNull(checkType, "CheckType cannot be null");
            this.value = Objects.requireNonNull(value, "Check value cannot be null").trim();
             if (this.value.isEmpty()) throw new IllegalArgumentException("Check value cannot be empty");
        }

        public int getOperandIndex() { return operandIndex; }
        public CheckType getCheckType() { return checkType; }
        public String getValue() { return value; }

         @Override
        public String toString() {
            return "OperandCheck{" +
                   "index=" + operandIndex +
                   ", type=" + checkType +
                   ", value='" + value + '\'' +
                   '}';
        }
    }
}
